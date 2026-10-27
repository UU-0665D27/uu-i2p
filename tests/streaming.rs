//! Тесты кодека `StreamingMessage` и I2NP-обёртки `Data`.
//!
//! Эталон формата — `libi2pd/Streaming.h:86-113` и
//! `Streaming.cpp:2538-2564` (порты в gzip-заголовке).

use uu_i2p::streaming::{
    FLAG_CLOSE, FLAG_FROM_INCLUDED, FLAG_SYNCHRONIZE, PROTOCOL_TYPE_STREAMING, StreamingPacket,
    unwrap_data_message, wrap_data_message,
};

#[test]
fn empty_packet_is_22_bytes() {
    let p = StreamingPacket::new(1, 2);
    let bytes = p.to_bytes().unwrap();
    // 17 до nackCount включительно + 1 resendDelay + 2 flags + 2 optionSize
    assert_eq!(bytes.len(), 22);
    assert_eq!(&bytes[0..4], &[0, 0, 0, 1]);
    assert_eq!(&bytes[4..8], &[0, 0, 0, 2]);
    assert_eq!(&bytes[12..16], &[0, 0, 0, 0]);
    assert_eq!(bytes[16], 0);
    assert_eq!(bytes[17], 0);
    assert_eq!(&bytes[18..20], &[0, 0]);
    assert_eq!(&bytes[20..22], &[0, 0]);
}

#[test]
fn roundtrip_full_packet() {
    let p = StreamingPacket {
        send_stream_id: 0x1122_3344,
        receive_stream_id: 0x5566_7788,
        seqn: 7,
        ack_through: 5,
        nacks: vec![6, 9],
        resend_delay: 3,
        flags: FLAG_SYNCHRONIZE | FLAG_FROM_INCLUDED,
        options: b"identity".to_vec(),
        payload: b"hello".to_vec(),
    };
    let bytes = p.to_bytes().unwrap();
    let (back, used) = StreamingPacket::from_buffer(&bytes).unwrap();
    assert_eq!(used, bytes.len());
    assert_eq!(back, p);
}

#[test]
fn from_buffer_reads_fields_from_i2pd_layout() {
    // Ровно то, что пишет i2pd в SYNACK: sendStreamID, receiveStreamID,
    // seqn=0, ackThrough=0, nackCount=0, resendDelay, flags, optionSize=0.
    let raw = [
        0x00, 0x00, 0x00, 0x09, // sendStreamID
        0x00, 0x00, 0x00, 0x0A, // receiveStreamID
        0x00, 0x00, 0x00, 0x00, // seqn
        0x00, 0x00, 0x00, 0x00, // ackThrough
        0x00, // nackCount
        0x02, // resendDelay
        0x00, 0x01, // flags SYNCHRONIZE
        0x00, 0x00, // optionSize
    ];
    let (p, _) = StreamingPacket::from_buffer(&raw).unwrap();
    assert_eq!(p.send_stream_id, 9);
    assert_eq!(p.receive_stream_id, 10);
    assert_eq!(p.seqn, 0);
    assert_eq!(p.nacks.len(), 0);
    assert_eq!(p.resend_delay, 2);
    assert!(p.is_syn());
    assert!(!p.is_close());
    assert_eq!(p.options.len(), 0);
}

#[test]
fn from_buffer_rejects_short_header() {
    assert!(StreamingPacket::from_buffer(&[0u8; 16]).is_err());
}

#[test]
fn from_buffer_rejects_truncated_nacks() {
    let mut raw = vec![0u8; 17];
    raw[16] = 8; // обещано 8 NACK'ов, а их нет
    assert!(StreamingPacket::from_buffer(&raw).is_err());
}

#[test]
fn from_buffer_rejects_truncated_options() {
    let mut raw = vec![0u8; 22];
    raw[20] = 0;
    raw[21] = 10; // optionSize = 10, данных нет
    assert!(StreamingPacket::from_buffer(&raw).is_err());
}

#[test]
fn nack_count_above_255_is_rejected() {
    let p = StreamingPacket {
        nacks: (0..256).collect(),
        ..StreamingPacket::new(1, 2)
    };
    assert!(p.to_bytes().is_err());
}

#[test]
fn close_flag_is_visible() {
    let mut p = StreamingPacket::new(1, 2);
    p.flags = FLAG_CLOSE;
    assert!(p.is_close());
    let bytes = p.to_bytes().unwrap();
    let (back, _) = StreamingPacket::from_buffer(&bytes).unwrap();
    assert!(back.is_close());
}

#[test]
fn data_message_roundtrip_keeps_ports_and_packet() {
    let p = StreamingPacket {
        seqn: 42,
        payload: b"payload".to_vec(),
        ..StreamingPacket::new(1, 2)
    };
    let packet = p.to_bytes().unwrap();
    let body = wrap_data_message(&packet, 1234, 5678).unwrap();

    // Тело — это 4-байтовая длина и gzip-контейнер, у которого
    // перезаписаны mtime/OS.
    let len = u32::from_be_bytes(body[0..4].try_into().unwrap()) as usize;
    assert_eq!(len, body.len() - 4);
    // Порты лежат в gzip-заголовке со смещения 4, а сам контейнер
    // начинается с body[4].
    assert_eq!(&body[8..10], &1234u16.to_be_bytes());
    assert_eq!(&body[10..12], &5678u16.to_be_bytes());
    assert_eq!(body[4 + 9], PROTOCOL_TYPE_STREAMING);
    // Магия gzip не тронута — иначе zlib не разберёт контейнер.
    assert_eq!(&body[4..6], &[0x1f, 0x8b]);

    let msg = unwrap_data_message(&body).unwrap();
    assert_eq!(msg.from_port, 1234);
    assert_eq!(msg.to_port, 5678);
    assert_eq!(msg.protocol, PROTOCOL_TYPE_STREAMING);
    let (back, _) = StreamingPacket::from_buffer(&msg.payload).unwrap();
    assert_eq!(back, p);
}

#[test]
fn unwrap_data_message_rejects_truncated() {
    assert!(unwrap_data_message(&[0u8; 8]).is_err());
}

#[test]
fn unwrap_data_message_rejects_length_past_buffer() {
    let mut body = vec![0u8; 14];
    body[0..4].copy_from_slice(&100u32.to_be_bytes());
    assert!(unwrap_data_message(&body).is_err());
}
