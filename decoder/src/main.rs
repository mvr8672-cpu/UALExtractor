// UALExtractor's read-only UFED adapter for macos-unifiedlogs 0.6.0.
// The upstream dependency is Apache-2.0 licensed; see THIRD_PARTY_NOTICES.md.

use macos_unifiedlogs::parser::{build_log, collect_timesync, parse_log};
use macos_unifiedlogs::traits::{FileProvider, SourceFile};
use macos_unifiedlogs::dsc::SharedCacheStrings;
use macos_unifiedlogs::uuidtext::UUIDText;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::collections::HashMap;

struct UfedFile {
    path: PathBuf,
    reader: File,
}

impl UfedFile {
    fn open(path: PathBuf) -> std::io::Result<Self> {
        Ok(Self {
            reader: File::open(&path)?,
            path,
        })
    }
}

impl SourceFile for UfedFile {
    fn reader(&mut self) -> Box<&mut dyn Read> {
        Box::new(&mut self.reader)
    }

    fn source_path(&self) -> &str {
        self.path.to_str().unwrap_or_default()
    }
}

struct UfedFileProvider {
    trace: PathBuf,
    uuidtext: PathBuf,
    dsc: Option<PathBuf>,
    timesync: PathBuf,
    uuid_cache: HashMap<String, UUIDText>,
    dsc_cache: HashMap<String, SharedCacheStrings>,
}

impl UfedFileProvider {
    fn files(path: &Path, suffix: Option<&str>) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Ok(entries) = walkdir::WalkDir::new(path).into_iter().collect::<Result<Vec<_>, _>>() {
            for entry in entries {
                let candidate = entry.path();
                if candidate.is_file()
                    && suffix.map(|value| candidate.extension().is_some_and(|ext| {
                        ext.to_string_lossy().eq_ignore_ascii_case(value)
                    })).unwrap_or(true)
                {
                    paths.push(candidate.to_path_buf());
                }
            }
        }
        paths.sort();
        paths
    }

    fn uuid_path(&self, uuid: &str) -> PathBuf {
        let normalized = match uuid.len() {
            30 => format!("00{uuid}"),
            31 => format!("0{uuid}"),
            _ => uuid.to_string(),
        };
        self.uuidtext.join(&normalized[0..2]).join(&normalized[2..])
    }
}

impl FileProvider for UfedFileProvider {
    fn tracev3_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>> {
        Box::new(
            UfedFile::open(self.trace.clone())
                .ok()
                .into_iter()
                .map(|file| Box::new(file) as Box<dyn SourceFile>),
        )
    }

    fn uuidtext_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>> {
        Box::new(Self::files(&self.uuidtext, None)
            .into_iter()
            .filter(|path| path.parent().and_then(Path::file_name).is_some_and(|name| {
                name.to_string_lossy().len() == 2
            }))
            .filter_map(|path| UfedFile::open(path).ok())
            .map(|file| Box::new(file) as Box<dyn SourceFile>))
    }

    fn read_uuidtext(&self, uuid: &str) -> Result<UUIDText, Error> {
        let path = self.uuid_path(uuid);
        let mut buffer = Vec::new();
        File::open(path)?.read_to_end(&mut buffer)?;
        UUIDText::parse_uuidtext(&buffer)
            .map(|(_, value)| value)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "failed to parse uuidtext"))
    }

    fn cached_uuidtext(&self, uuid: &str) -> Option<&UUIDText> {
        self.uuid_cache.get(uuid)
    }

    fn update_uuid(&mut self, uuid: &str, _uuid2: &str) {
        if let Ok(value) = self.read_uuidtext(uuid) {
            self.uuid_cache.insert(uuid.to_string(), value);
        }
    }

    fn dsc_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>> {
        Box::new(self.dsc.as_ref()
            .map(|path| Self::files(path, None))
            .into_iter()
            .flatten()
            .filter_map(|path| UfedFile::open(path).ok())
            .map(|file| Box::new(file) as Box<dyn SourceFile>))
    }

    fn read_dsc_uuid(&self, uuid: &str) -> Result<SharedCacheStrings, Error> {
        let path = self.dsc.as_ref().ok_or_else(|| {
            Error::new(ErrorKind::NotFound, "dsc path was not supplied")
        })?.join(uuid);
        let mut buffer = Vec::new();
        File::open(path)?.read_to_end(&mut buffer)?;
        SharedCacheStrings::parse_dsc(&buffer)
            .map(|(_, value)| value)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "failed to parse dsc"))
    }

    fn cached_dsc(&self, uuid: &str) -> Option<&SharedCacheStrings> {
        self.dsc_cache.get(uuid)
    }

    fn update_dsc(&mut self, uuid: &str, _uuid2: &str) {
        if let Ok(value) = self.read_dsc_uuid(uuid) {
            self.dsc_cache.insert(uuid.to_string(), value);
        }
    }

    fn timesync_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>> {
        Box::new(Self::files(&self.timesync, Some("timesync"))
            .into_iter()
            .filter_map(|path| UfedFile::open(path).ok())
            .map(|file| Box::new(file) as Box<dyn SourceFile>))
    }
}

fn argument(name: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .unwrap_or_else(|| {
            eprintln!("missing required argument {name}");
            std::process::exit(2);
        })
}

fn main() {
    if std::env::args().any(|argument| argument == "--help" || argument == "-h") {
        println!("ualextractor-decoder 0.1.0");
        println!("Read-only single-trace UFED decoder");
        println!("  --trace PATH --diagnostics PATH --uuidtext PATH --timesync PATH [--dsc PATH]");
        return;
    }
    let trace = PathBuf::from(argument("--trace"));
    let diagnostics = PathBuf::from(argument("--diagnostics"));
    let uuidtext = PathBuf::from(argument("--uuidtext"));
    let timesync = PathBuf::from(argument("--timesync"));
    let dsc = std::env::args().collect::<Vec<_>>().windows(2)
        .find(|pair| pair[0] == "--dsc")
        .map(|pair| PathBuf::from(&pair[1]));

    let mut provider = UfedFileProvider {
        trace: trace.clone(),
        uuidtext,
        dsc,
        timesync,
        uuid_cache: HashMap::new(),
        dsc_cache: HashMap::new(),
    };
    let timesync_data = collect_timesync(&provider)
        .unwrap_or_else(|error| {
            eprintln!("timesync diagnostic: {error:?}");
            Default::default()
        });
    let mut reader = File::open(&trace).unwrap_or_else(|error| {
        eprintln!("trace diagnostic: {error}");
        std::process::exit(1);
    });
    let parsed = parse_log(&mut reader, trace.to_str().unwrap_or_default())
        .unwrap_or_else(|error| {
            eprintln!("trace diagnostic: {error:?}");
            std::process::exit(1);
        });
    let (records, missing) = build_log(
        &parsed,
        &mut provider,
        &timesync_data,
        true,
    );
    if !missing.oversize.is_empty() {
        eprintln!("decoder diagnostic: unresolved oversize data remains");
    }
    for record in records {
        let value = serde_json::json!({
            "timestamp": record.timestamp,
            "process": record.process,
            "pid": record.pid,
            "subsystem": record.subsystem,
            "category": record.category,
            "log_type": record.log_type,
            "event_type": record.event_type,
            "message": record.message,
            "source_trace_path": record.evidence,
        });
        println!("{}", value);
    }
    let _ = diagnostics;
}
