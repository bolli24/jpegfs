use anyhow::Context;
use crossterm::{
	event::{self, Event, KeyCode, KeyEventKind},
	execute,
	terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use ratatui::{
	Terminal,
	backend::CrosstermBackend,
	layout::{Constraint, Direction, Layout},
	style::{Color, Modifier, Style},
	text::{Line, Span},
	widgets::{Block, Borders, Paragraph},
};
use std::{
	collections::{HashMap, VecDeque},
	io,
	path::Path,
	sync::mpsc::{Receiver, SyncSender, TryRecvError},
	time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use jpegfs::filesystem::{FileSystem, FsDashboardStats, BLOCK_SIZE};

const LOG_BUFFER_CAPACITY: usize = 2_000;
const OP_RATE_WINDOW: Duration = Duration::from_secs(10);
const STATS_TICK: Duration = Duration::from_millis(500);

#[derive(Clone, Debug)]
pub struct LogEvent {
	pub level: Level,
	pub timestamp: String,
	pub message: String,
}

struct TuiLogger {
	tx: SyncSender<LogEvent>,
}

impl Log for TuiLogger {
	fn enabled(&self, metadata: &Metadata) -> bool {
		metadata.level() <= log::max_level()
	}

	fn log(&self, record: &Record) {
		if !self.enabled(record.metadata()) {
			return;
		}

		let _ = self.tx.try_send(LogEvent {
			level: record.level(),
			timestamp: now_hms_utc(),
			message: record.args().to_string(),
		});
	}

	fn flush(&self) {}
}

pub fn init_tui_logger(tx: SyncSender<LogEvent>) -> Result<(), SetLoggerError> {
	log::set_boxed_logger(Box::new(TuiLogger { tx }))?;
	log::set_max_level(LevelFilter::Info);
	Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogFilter {
	Info,
	Warn,
	Error,
}

impl LogFilter {
	fn next(self) -> Self {
		match self {
			Self::Info => Self::Warn,
			Self::Warn => Self::Error,
			Self::Error => Self::Info,
		}
	}

	fn allows(self, level: Level) -> bool {
		match self {
			Self::Info => matches!(level, Level::Info | Level::Warn | Level::Error),
			Self::Warn => matches!(level, Level::Warn | Level::Error),
			Self::Error => level == Level::Error,
		}
	}

	fn label(self) -> &'static str {
		match self {
			Self::Info => "INFO+",
			Self::Warn => "WARN+",
			Self::Error => "ERROR",
		}
	}
}

#[derive(Default)]
struct OpCounters {
	total: u64,
	by_op: HashMap<String, u64>,
	recent: VecDeque<Instant>,
}

impl OpCounters {
	fn record(&mut self, op: &str, now: Instant) {
		self.total = self.total.saturating_add(1);
		*self.by_op.entry(op.to_string()).or_insert(0) += 1;
		self.recent.push_back(now);
		self.prune(now);
	}

	fn prune(&mut self, now: Instant) {
		while let Some(front) = self.recent.front().copied() {
			if now.duration_since(front) <= OP_RATE_WINDOW {
				break;
			}
			self.recent.pop_front();
		}
	}

	fn rate_10s(&mut self, now: Instant) -> u64 {
		self.prune(now);
		self.recent.len() as u64
	}

	fn top3(&self) -> Vec<(&str, u64)> {
		let mut entries: Vec<(&str, u64)> = self.by_op.iter().map(|(op, count)| (op.as_str(), *count)).collect();
		entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
		entries.truncate(3);
		entries
	}
}

struct AppState {
	mount_path: String,
	started_at: Instant,
	stats: FsDashboardStats,
	logs: VecDeque<LogEvent>,
	filter: LogFilter,
	scroll: u16,
	follow_tail: bool,
	op_counters: OpCounters,
}

impl AppState {
	fn new(mount_path: &Path, stats: FsDashboardStats) -> Self {
		Self {
			mount_path: mount_path.display().to_string(),
			started_at: Instant::now(),
			stats,
			logs: VecDeque::with_capacity(LOG_BUFFER_CAPACITY),
			filter: LogFilter::Info,
			scroll: 0,
			follow_tail: true,
			op_counters: OpCounters::default(),
		}
	}

	fn push_log(&mut self, event: LogEvent, now: Instant) {
		if let Some(op) = parse_op_name(&event.message) {
			self.op_counters.record(op, now);
		}

		if self.logs.len() >= LOG_BUFFER_CAPACITY {
			self.logs.pop_front();
		}
		self.logs.push_back(event);
	}

	fn filtered_logs(&self) -> Vec<&LogEvent> {
		self.logs
			.iter()
			.filter(|event| self.filter.allows(event.level))
			.collect()
	}

	fn clear_logs(&mut self) {
		self.logs.clear();
		self.scroll = 0;
		self.follow_tail = true;
	}

	fn cycle_filter(&mut self) {
		self.filter = self.filter.next();
		self.scroll = 0;
		self.follow_tail = true;
	}

	fn refresh_stats(&mut self, fs: &FileSystem) {
		let state = fs.state.read();
		self.stats = state.dashboard_stats();
	}
}

pub fn run_tui(
	fs: &FileSystem,
	mount_path: &Path,
	log_rx: &Receiver<LogEvent>,
	shutdown_rx: &Receiver<()>,
) -> anyhow::Result<()> {
	let initial_stats = {
		let state = fs.state.read();
		state.dashboard_stats()
	};
	let mut app = AppState::new(mount_path, initial_stats);

	enable_raw_mode().context("failed to enable raw mode")?;
	let mut stdout = io::stdout();
	execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
	let backend = CrosstermBackend::new(stdout);
	let mut terminal = Terminal::new(backend).context("failed to create terminal")?;
	terminal.clear().context("failed to clear terminal")?;

	let run_result = run_event_loop(&mut terminal, fs, log_rx, shutdown_rx, &mut app);

	disable_raw_mode().context("failed to disable raw mode")?;
	execute!(terminal.backend_mut(), LeaveAlternateScreen).context("failed to leave alternate screen")?;
	terminal.show_cursor().context("failed to show cursor")?;

	run_result
}

fn run_event_loop(
	terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
	fs: &FileSystem,
	log_rx: &Receiver<LogEvent>,
	shutdown_rx: &Receiver<()>,
	app: &mut AppState,
) -> anyhow::Result<()> {
	let mut last_tick = Instant::now();

	loop {
		let now = Instant::now();
		let mut saw_log = false;
		loop {
			match log_rx.try_recv() {
				Ok(event) => {
					app.push_log(event, now);
					saw_log = true;
				}
				Err(TryRecvError::Empty) => break,
				Err(TryRecvError::Disconnected) => break,
			}
		}

		if saw_log || now.duration_since(last_tick) >= STATS_TICK {
			app.refresh_stats(fs);
			last_tick = now;
		}

		app.op_counters.prune(now);

		terminal
			.draw(|frame| draw_ui(frame, app, now))
			.context("failed to draw tui frame")?;

		if shutdown_rx.try_recv().is_ok() {
			break;
		}

		let timeout = STATS_TICK
			.saturating_sub(now.duration_since(last_tick))
			.min(Duration::from_millis(100));
		if event::poll(timeout).context("failed to poll terminal events")? {
			let Event::Key(key) = event::read().context("failed to read terminal event")? else {
				continue;
			};
			if key.kind != KeyEventKind::Press {
				continue;
			}

			match key.code {
				KeyCode::Char('q') => break,
				KeyCode::Char('f') => app.cycle_filter(),
				KeyCode::Char('c') => app.clear_logs(),
				KeyCode::Up => {
					app.follow_tail = false;
					app.scroll = app.scroll.saturating_sub(1);
				}
				KeyCode::Down => {
					app.scroll = app.scroll.saturating_add(1);
				}
				_ => {}
			}
		}
	}

	Ok(())
}

fn draw_ui(frame: &mut ratatui::Frame<'_>, app: &mut AppState, now: Instant) {
	let root = frame.area();
	let layout = Layout::default()
		.direction(Direction::Vertical)
		.constraints([Constraint::Length(7), Constraint::Min(5), Constraint::Length(1)])
		.split(root);

	let top = Layout::default()
		.direction(Direction::Horizontal)
		.constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
		.split(layout[0]);

	let used_pct = if app.stats.total_blocks == 0 {
		0.0
	} else {
		(app.stats.used_blocks as f64 / app.stats.total_blocks as f64) * 100.0
	};
	let stats_text = vec![
		Line::from(format!(
			"Blocks: {} / {} (free: {}, {:.1}%)",
			app.stats.used_blocks, app.stats.total_blocks, app.stats.free_blocks, used_pct
		)),
		Line::from(format!(
			"{} KiB / {} KiB (free: {} KiB)",
			app.stats.used_blocks * BLOCK_SIZE / 1024, app.stats.total_blocks * BLOCK_SIZE / 1024, app.stats.free_blocks * BLOCK_SIZE / 1024
		)),
		Line::from(format!(
			"Files: {}    Dirs: {}    Open handles: {}",
			app.stats.file_count, app.stats.directory_count, app.stats.open_handles
		)),
		Line::from(format!(
			"Page split: inodes={} dir_entries={} data={}",
			app.stats.inode_blocks, app.stats.dir_entry_blocks, app.stats.data_blocks
		)),
	];
	let stats = Paragraph::new(stats_text).block(Block::default().title("Filesystem").borders(Borders::ALL));
	frame.render_widget(stats, top[0]);

	let rate = app.op_counters.rate_10s(now);
	let top_ops = app.op_counters.top3();
	let top_ops_line = if top_ops.is_empty() {
		"Top ops: -".to_string()
	} else {
		format!(
			"Top ops: {}",
			top_ops
				.into_iter()
				.map(|(op, count)| format!("{op}:{count}"))
				.collect::<Vec<_>>()
				.join("  ")
		)
	};
	let ops_text = vec![
		Line::from(format!("Ops total: {}", app.op_counters.total)),
		Line::from(format!("Ops/10s: {rate}")),
		Line::from(top_ops_line),
		Line::from(format!("Log filter: {}", app.filter.label())),
	];
	let ops = Paragraph::new(ops_text).block(Block::default().title("Activity").borders(Borders::ALL));
	frame.render_widget(ops, top[1]);

	let filtered = app.filtered_logs();
	let lines: Vec<Line<'_>> = filtered
		.iter()
		.map(|event| {
			let color = match event.level {
				Level::Error => Color::Red,
				Level::Warn => Color::Yellow,
				_ => Color::Cyan,
			};
			Line::from(vec![
				Span::styled(
					format!("[{}][{}] ", event.timestamp, event.level),
					Style::default().fg(color).add_modifier(Modifier::BOLD),
				),
				Span::raw(event.message.clone()),
			])
		})
		.collect();

	let log_height = layout[1].height.saturating_sub(2) as usize;
	let max_scroll = filtered.len().saturating_sub(log_height) as u16;
	if app.follow_tail {
		app.scroll = max_scroll;
	} else if app.scroll >= max_scroll {
		app.scroll = max_scroll;
		app.follow_tail = true;
	}

	let logs = Paragraph::new(lines)
		.block(Block::default().title("Log").borders(Borders::ALL))
		.scroll((app.scroll, 0));
	frame.render_widget(logs, layout[1]);

	let uptime = now.duration_since(app.started_at).as_secs();
	let status = Paragraph::new(format!(
		"mount={} | uptime={}s | keys: q quit, f filter, c clear, ↑/↓ scroll",
		app.mount_path, uptime
	));
	frame.render_widget(status, layout[2]);
}

fn now_hms_utc() -> String {
	let secs = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
		% 86_400;
	let h = secs / 3600;
	let m = (secs % 3600) / 60;
	let s = secs % 60;
	format!("{h:02}:{m:02}:{s:02}")
}

fn parse_op_name(message: &str) -> Option<&str> {
	let split = message.find('(')?;
	let name = &message[..split];
	if name.is_empty() {
		return None;
	}
	if name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
		Some(name)
	} else {
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_op_name_extracts_fuse_operations() {
		assert_eq!(parse_op_name("mkdir(parent=1, name=\"a\")"), Some("mkdir"));
		assert_eq!(parse_op_name("copy_file_range(ino=1)"), Some("copy_file_range"));
		assert_eq!(parse_op_name("initialized filesystem capacity: 123"), None);
		assert_eq!(parse_op_name("[Not Implemented] readlink(ino=1)"), None);
	}

	#[test]
	fn op_counter_tracks_window_and_total() {
		let mut counters = OpCounters::default();
		let base = Instant::now();
		counters.record("mkdir", base);
		counters.record("mkdir", base + Duration::from_secs(1));
		counters.record("create", base + Duration::from_secs(2));
		assert_eq!(counters.total, 3);
		assert_eq!(counters.rate_10s(base + Duration::from_secs(5)), 3);
		assert_eq!(counters.rate_10s(base + Duration::from_secs(12)), 1);
		assert_eq!(counters.rate_10s(base + Duration::from_secs(13)), 0);
	}
}
