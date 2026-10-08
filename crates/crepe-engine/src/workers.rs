//! Bounded live workers. IP-pair affinity keeps both directions and all fragments together.
use super::{Config, Input, Sink};
use crepe_core::{Error, EventHeader, PacketEvent, Result};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
struct Packet {
    data: Vec<u8>,
    header: EventHeader,
    link: u32,
}
enum Work {
    Packet(Box<Packet>),
    Tick(i128),
}
enum Output {
    Packet(Box<PacketEvent>, Option<u64>),
    Flow(Box<crepe_flow::FlowRecord>),
    Analysis(Box<crepe_analysis::Event>),
    Malformed(EventHeader, Error),
    Finished(usize, u64, u64),
}
fn channel_error() -> Error {
    Error::new("CREPE-ENGINE-001", "analysis worker channel closed")
}
fn affinity(record: &crepe_capture::Record<'_>, workers: usize) -> usize {
    let Ok(Some(packet)) = record.decode() else {
        return 0;
    };
    let (a, b) = if packet.src.ip <= packet.dst.ip {
        (packet.src.ip, packet.dst.ip)
    } else {
        (packet.dst.ip, packet.src.ip)
    };
    // Ports and terminal protocol are excluded: later IPv6 fragments may hide post-fragment extension headers.
    let hash = crepe_storage::identity(&[
        &a.to_string(),
        &b.to_string(),
        &packet.header.section.to_string(),
        &packet.header.interface.to_string(),
        &format!("{:?}", packet.vlans),
    ]);
    (u64::from_str_radix(&hash[..16], 16).expect("identity is hexadecimal") % workers as u64)
        as usize
}
fn worker(
    config: &Config,
    input: Receiver<Work>,
    output: &SyncSender<Result<Output>>,
) -> Result<()> {
    let send = |value| output.send(Ok(value)).map_err(|_| channel_error());
    let mut analyzer = crepe_analysis::Processor::partition(
        crepe_analysis::Config {
            dns_ports: vec![config.dns_port],
            max_streams: config.max_streams / config.workers,
            max_buffer_bytes: config.max_buffer_bytes / config.workers,
            ..Default::default()
        },
        config.workers,
    )?;
    let mut flows = crepe_flow::FlowTable::new(crepe_flow::Config {
        max_flows: 65536 / config.workers,
        ..Default::default()
    })?;
    for work in input {
        match work {
            Work::Tick(now) => {
                if config.flows() {
                    flows.advance(now, |flow| send(Output::Flow(Box::new(flow))))?;
                }
                if config.analysis() {
                    analyzer
                        .analyzer
                        .advance(now, |event| send(Output::Analysis(Box::new(event))))?;
                    analyzer.fragments.expire(now)?;
                }
            }
            Work::Packet(packet) => {
                let record = crepe_capture::Record {
                    data: &packet.data,
                    header: packet.header,
                    linktype: packet.link,
                };
                let decoded = match record.decode() {
                    Ok(value) => value,
                    Err(error) if config.tolerant_decode && error.code == "CREPE-PKT-001" => {
                        send(Output::Malformed(record.header, error))?;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if let Some(packet) = decoded {
                    let anchor = if config.flows() && packet.header.timestamp_ns.is_some() {
                        flows.push(&packet, |flow| send(Output::Flow(Box::new(flow))))?;
                        flows.last_assignment()
                    } else {
                        None
                    };
                    send(Output::Packet(Box::new(packet), anchor))?;
                }
                if config.analysis() {
                    if let Err(error) = analyzer.process(
                        record.data,
                        record.header.clone(),
                        record.linktype,
                        |event| send(Output::Analysis(Box::new(event))),
                    ) {
                        if config.tolerant_decode && error.code == "CREPE-PKT-001" {
                            send(Output::Malformed(record.header, error))?;
                        } else {
                            return Err(error);
                        }
                    }
                }
            }
        }
    }
    if config.flows() {
        flows.finish(|flow| send(Output::Flow(Box::new(flow))))?;
    }
    if config.analysis() {
        let incomplete = analyzer.finish(|event| send(Output::Analysis(Box::new(event))))?;
        send(Output::Finished(
            incomplete,
            analyzer.fragments.stats.expired,
            analyzer.fragments.stats.evicted,
        ))?;
    }
    Ok(())
}
fn accept(value: Result<Output>, sink: &mut Sink<'_, '_>) -> Result<()> {
    match value? {
        Output::Packet(packet, anchor) => sink.packet(&packet, anchor),
        Output::Flow(flow) => sink.flow(*flow),
        Output::Analysis(event) => sink.analysis(*event),
        Output::Malformed(header, error) => sink.malformed(&header, &error),
        Output::Finished(incomplete, expired, evicted) => {
            sink.summary.incomplete_datagrams += incomplete;
            sink.summary.expired_datagrams += expired;
            sink.summary.evicted_datagrams += evicted;
            Ok(())
        }
    }
}
fn drain(output: &Receiver<Result<Output>>, sink: &mut Sink<'_, '_>) -> Result<()> {
    while let Ok(value) = output.try_recv() {
        accept(value, sink)?;
    }
    Ok(())
}
fn dispatch(
    sender: &SyncSender<Work>,
    mut work: Work,
    output: &Receiver<Result<Output>>,
    sink: &mut Sink<'_, '_>,
) -> Result<()> {
    loop {
        match sender.try_send(work) {
            Ok(()) => return drain(output, sink),
            Err(TrySendError::Disconnected(_)) => return Err(channel_error()),
            Err(TrySendError::Full(value)) => {
                work = value;
                match output.recv_timeout(std::time::Duration::from_millis(10)) {
                    Ok(value) => accept(value, sink)?,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => return Err(channel_error()),
                }
            }
        }
    }
}
pub(super) fn run(
    config: &Config,
    read: impl FnOnce(&mut dyn FnMut(Input<'_>) -> Result<bool>) -> Result<()>,
    sink: &mut Sink<'_, '_>,
) -> Result<()> {
    std::thread::scope(|scope| {
        let (send_output, output) = mpsc::sync_channel(128);
        let mut inputs = Vec::new();
        let mut handles = Vec::new();
        for _ in 0..config.workers {
            let (send, receive) = mpsc::sync_channel(16);
            inputs.push(send);
            let output = send_output.clone();
            handles.push(scope.spawn(move || {
                let result = worker(config, receive, &output);
                if let Err(error) = &result {
                    let _ = output.send(Err(Error::new(error.code, &error.message)));
                }
                result
            }));
        }
        drop(send_output);
        let mut result = read(&mut |input| {
            drain(&output, sink)?;
            match input {
                Input::Packet(record) => {
                    if record.data.len() > 65535 {
                        return Err(Error::new(
                            "CREPE-ENGINE-001",
                            "live worker record exceeds 65535 bytes",
                        ));
                    }
                    sink.summary.packets += 1;
                    let index = affinity(&record, config.workers);
                    dispatch(
                        &inputs[index],
                        Work::Packet(Box::new(Packet {
                            data: record.data.to_vec(),
                            header: record.header,
                            link: record.linktype,
                        })),
                        &output,
                        sink,
                    )?;
                }
                Input::Tick(now) => {
                    for input in &inputs {
                        dispatch(input, Work::Tick(now), &output, sink)?;
                    }
                    sink.maybe_checkpoint()?;
                }
                Input::Observation(row) => {
                    if row.sensor != config.sensor || row.source != sink.source {
                        return Err(Error::new(
                            "CREPE-ENGINE-001",
                            "external observation has a different sensor/source",
                        ));
                    }
                    if config.accepts(&row.event_type) {
                        if row.event_type.starts_with("notice.")
                            || row.event_type.starts_with("anomaly.")
                        {
                            sink.summary.notices += 1;
                        }
                        sink.push(*row)?;
                    }
                }
            }
            Ok(true)
        });
        drop(inputs);
        if result.is_ok() {
            for value in &output {
                if let Err(error) = accept(value, sink) {
                    result = Err(error);
                    break;
                }
            }
        }
        // Release blocked senders before joining on an output/read failure.
        drop(output);
        for handle in handles {
            let may_replace = result
                .as_ref()
                .err()
                .is_none_or(|e| e.message == "analysis worker channel closed");
            match handle.join() {
                Ok(Err(error)) if may_replace => result = Err(error),
                Err(_) if may_replace => {
                    result = Err(Error::new("CREPE-ENGINE-001", "analysis worker panicked"))
                }
                _ => {}
            }
        }
        result
    })
}
