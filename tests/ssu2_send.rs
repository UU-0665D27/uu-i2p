use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use uu_i2p::{
    error::I2PError,
    i2np::{I2npHeader, I2npMessageType},
    i2np_message::I2npMessage,
    ssu2_ack::Ssu2AckBlock,
    ssu2_block::{
        AddressBlock, Blocks, FirstFragmentBlock, FollowOnFragmentBlock, Ssu2Block, Ssu2BlockType,
    },
    ssu2_fragments::IncompleteMessages,
    ssu2_header::SSU2_FLAG_IMMEDIATE_ACK_REQUESTED,
    ssu2_policy::{I2pdPolicy, Ssu2Policy},
    ssu2_send,
};

/// Разбирает payload на пары `(тип, тело)`.
fn blocks(payload: &[u8]) -> Vec<(Ssu2BlockType, Vec<u8>)> {
    Blocks::new(payload)
        .map(|b| {
            let b = b.expect("block parses");
            (b.kind().expect("registered type"), b.body.to_vec())
        })
        .collect()
}

fn empty_ack() -> Ssu2AckBlock {
    Ssu2AckBlock {
        ack_through: 0,
        acnt: 0,
        ranges: Vec::new(),
    }
}

fn v4() -> AddressBlock {
    AddressBlock {
        port: 12345,
        ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
    }
}

// ---- SendQuickAck -------------------------------------------------------

#[test]
fn quick_ack_without_datetime() {
    let p = I2pdPolicy;
    let ack = Ssu2AckBlock {
        ack_through: 10,
        acnt: 5,
        ranges: Vec::new(),
    };
    let mut last = 0u32;
    let out = ssu2_send::quick_ack(10, &mut last, &ack, 0, 1000, 1200, &p).expect("ok");
    assert_eq!(out.flags, 0);
    let b = blocks(&out.payload);
    assert_eq!(b.len(), 2);
    assert_eq!(b[0].0, Ssu2BlockType::Ack);
    assert_eq!(b[0].1, ack.to_body());
    assert_eq!(b[1].0, Ssu2BlockType::Padding);
    assert_eq!(last, 0, "без DateTime счётчик не двигается");
}

#[test]
fn quick_ack_with_datetime() {
    let p = I2pdPolicy;
    let mut last = 0u32;
    let out = ssu2_send::quick_ack(257, &mut last, &empty_ack(), 0, 12345, 1200, &p).expect("ok");
    assert_eq!(last, 257);
    let b = blocks(&out.payload);
    assert_eq!(b[0].0, Ssu2BlockType::DateTime);
    assert_eq!(b[0].1, 12345u32.to_be_bytes().to_vec());
    assert_eq!(b[1].0, Ssu2BlockType::Ack);
    assert_eq!(b[2].0, Ssu2BlockType::Padding);
}

#[test]
fn quick_ack_datetime_boundary_is_strict() {
    let p = I2pdPolicy;
    // ровно `last + 256` — ещё без DateTime (`>` строгий)
    let mut last = 0u32;
    let at = ssu2_send::quick_ack(256, &mut last, &empty_ack(), 0, 1, 1200, &p).expect("ok");
    assert_eq!(blocks(&at.payload)[0].0, Ssu2BlockType::Ack);
    assert_eq!(last, 0);
    // `last + 257` — уже с DateTime
    let mut last = 0u32;
    let over = ssu2_send::quick_ack(257, &mut last, &empty_ack(), 0, 1, 1200, &p).expect("ok");
    assert_eq!(blocks(&over.payload)[0].0, Ssu2BlockType::DateTime);
    assert_eq!(last, 257);
}

#[test]
fn quick_ack_datetime_interval_respects_last() {
    let p = I2pdPolicy;
    let mut last = 100u32;
    // 100 + 256 = 356; 356 > 356 — нет
    let at = ssu2_send::quick_ack(356, &mut last, &empty_ack(), 0, 1, 1200, &p).expect("ok");
    assert_eq!(blocks(&at.payload)[0].0, Ssu2BlockType::Ack);
    assert_eq!(last, 100);
}

#[test]
fn quick_ack_padding_uses_roll_mask() {
    let p = I2pdPolicy;
    let mut last = 0u32;
    // roll & 0x1F == 31
    let out = ssu2_send::quick_ack(0, &mut last, &empty_ack(), 0xFF, 1, 1200, &p).expect("ok");
    let pad = blocks(&out.payload).pop().expect("padding");
    assert_eq!(pad.0, Ssu2BlockType::Padding);
    assert_eq!(pad.1.len(), 31);
}

// ---- SendKeepAlive ------------------------------------------------------

#[test]
fn keep_alive_has_min_padding_and_flag() {
    let p = I2pdPolicy;
    let out = ssu2_send::keep_alive(0, &p).expect("ok");
    assert_eq!(out.flags, SSU2_FLAG_IMMEDIATE_ACK_REQUESTED);
    assert_eq!(
        out.payload.len(),
        8,
        "roll=0 поднят до минимального блока 8"
    );
    let b = blocks(&out.payload);
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].0, Ssu2BlockType::Padding);
    assert_eq!(b[0].1.len(), 5);
}

#[test]
fn keep_alive_is_clamped_to_20_bytes() {
    let p = I2pdPolicy;
    let out = ssu2_send::keep_alive(0xFF, &p).expect("ok");
    assert_eq!(out.payload.len(), 20);
    assert_eq!(blocks(&out.payload)[0].1.len(), 17);
}

// ---- SendTermination ----------------------------------------------------

#[test]
fn termination_layout() {
    let p = I2pdPolicy;
    let out = ssu2_send::termination(0x0000_0000_dead_beef, 5, 0, &p).expect("ok");
    assert_eq!(out.flags, 0);
    assert!(out.payload.len() <= 32, "payload {}", out.payload.len());
    let b = blocks(&out.payload);
    assert_eq!(b[0].0, Ssu2BlockType::Termination);
    assert_eq!(b[0].1.len(), 9);
    assert_eq!(&b[0].1[..8], &0x0000_0000_dead_beefu64.to_be_bytes());
    assert_eq!(b[0].1[8], 5);
    assert_eq!(b[1].0, Ssu2BlockType::Padding);
}

// ---- SendPathChallenge / SendPathResponse -------------------------------

#[test]
fn path_challenge_layout() {
    let p = I2pdPolicy;
    let addr = v4();
    let ack = Ssu2AckBlock {
        ack_through: 7,
        acnt: 3,
        ranges: Vec::new(),
    };
    let out =
        ssu2_send::path_challenge(&addr, 0x1122_3344_5566_7788, &ack, 0, 99, 1200, &p).expect("ok");
    assert_eq!(out.flags, 0);
    let b = blocks(&out.payload);
    let kinds: Vec<_> = b.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        kinds,
        vec![
            Ssu2BlockType::DateTime,
            Ssu2BlockType::Address,
            Ssu2BlockType::PathChallenge,
            Ssu2BlockType::Ack,
            Ssu2BlockType::Padding,
        ]
    );
    assert_eq!(b[0].1, 99u32.to_be_bytes().to_vec());
    assert_eq!(b[1].1, addr.to_body());
    assert_eq!(b[2].1, 0x1122_3344_5566_7788u64.to_be_bytes().to_vec());
    assert_eq!(b[3].1, ack.to_body());
}

#[test]
fn path_response_layout() {
    let p = I2pdPolicy;
    let addr = AddressBlock {
        port: 1,
        ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
    };
    let data = [9u8, 8, 7, 6, 5, 4, 3, 2];
    let out = ssu2_send::path_response(&addr, &data, &empty_ack(), 0, 42, 1200, &p).expect("ok");
    let b = blocks(&out.payload);
    let kinds: Vec<_> = b.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        kinds,
        vec![
            Ssu2BlockType::DateTime,
            Ssu2BlockType::Address,
            Ssu2BlockType::PathResponse,
            Ssu2BlockType::Ack,
            Ssu2BlockType::Padding,
        ]
    );
    assert_eq!(b[1].1, addr.to_body());
    assert_eq!(b[2].1, data.to_vec());
}

#[test]
fn path_response_rejects_oversized_data() {
    let p = I2pdPolicy;
    let data = vec![0u8; 1200];
    let err = ssu2_send::path_response(&v4(), &data, &empty_ack(), 0, 42, 1200, &p)
        .expect_err("data does not fit");
    assert!(
        matches!(err, I2PError::InvalidLength { .. }),
        "unexpected {err:?}"
    );
}

#[test]
fn path_challenge_omits_address_without_room() {
    let p = I2pdPolicy;
    let addr = AddressBlock {
        port: 1,
        ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
    };
    // DateTime (7) + IPV6-Address (21) не влезает в 25 байт
    let out = ssu2_send::path_challenge(&addr, 0, &empty_ack(), 0, 1, 25, &p).expect("ok");
    let b = blocks(&out.payload);
    assert_eq!(b[0].0, Ssu2BlockType::DateTime);
    assert!(
        b.iter().all(|(k, _)| *k != Ssu2BlockType::Address),
        "Address не должен появиться"
    );
}

// ---- SendFragmentedMessage ---------------------------------------------

/// Детерминированный источник «бросков»: значения по порядку, последнее
/// залипает (чтобы хватило на любое число вызовов).
struct Rolls {
    values: Vec<u32>,
    index: usize,
}

impl Rolls {
    fn constant(value: u32) -> Self {
        Self {
            values: vec![value],
            index: 0,
        }
    }

    fn sequence(values: Vec<u32>) -> Self {
        assert!(!values.is_empty(), "sequence must not be empty");
        Self { values, index: 0 }
    }
}

impl ssu2_send::RandomSource for Rolls {
    fn roll(&mut self) -> u32 {
        let i = self.index.min(self.values.len() - 1);
        self.index += 1;
        self.values[i]
    }
}

/// I2NP-сообщение с фиксированным `msg_id`/expiration (детерминизм).
fn message(payload_len: usize) -> I2npMessage {
    let header = I2npHeader {
        message_type: I2npMessageType::Data,
        msg_id: 0x0102_0304,
        expiration_ms: 1_700_000_000_000,
        size: u16::try_from(payload_len).expect("payload fits"),
        checksum: None,
    };
    I2npMessage::with_header(header, vec![0xAB; payload_len])
}

/// Прогоняет пакеты плана через сборку фрагментов и возвращает собранное
/// сообщение (или `None`, если его так и не собрали).
fn reassemble(plan: &ssu2_send::FragmentedPlan, max_fragments: u8) -> Option<I2npMessage> {
    let now = Duration::from_secs(0);
    let mut incomplete = IncompleteMessages::new();
    for packet in &plan.packets {
        for (kind, body) in blocks(&packet.payload) {
            match kind {
                Ssu2BlockType::FirstFragment => {
                    let block = FirstFragmentBlock::parse(&body).expect("first fragment");
                    if let Some(msg) = incomplete.handle_first_fragment(&block, now) {
                        return Some(msg);
                    }
                }
                Ssu2BlockType::FollowOnFragment => {
                    let block = FollowOnFragmentBlock::parse(&body).expect("follow-on");
                    if let Some(msg) =
                        incomplete.handle_follow_on_fragment(&block, now, max_fragments)
                    {
                        return Some(msg);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

#[test]
fn fragmented_message_fits_single_block() {
    let p = I2pdPolicy;
    // ntcp2_len = 29, ntcp2_len + 3 = 32 <= 100
    let msg = message(20);
    let mut rng = Rolls::constant(0);
    let plan = ssu2_send::fragmented_message(&msg, 100, &empty_ack(), &mut rng, &p).expect("ok");
    assert_eq!(plan.packets.len(), 1);
    assert!(!plan.ack_block_sent);
    assert!(!plan.aborted);
    assert_eq!(plan.packets[0].flags, 0);
    let b = blocks(&plan.packets[0].payload);
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].0, Ssu2BlockType::I2npMessage);
    assert_eq!(I2npMessage::from_ntcp2_bytes(&b[0].1).expect("i2np"), msg);
}

#[test]
fn fragmented_message_splits_and_reassembles() {
    let p = I2pdPolicy;
    // ntcp2_len = 189: первый фрагмент несёт 97 байт, продолжение — 92.
    let msg = message(180);
    let mut rng = Rolls::constant(0);
    let plan = ssu2_send::fragmented_message(&msg, 100, &empty_ack(), &mut rng, &p).expect("ok");
    assert!(plan.ack_block_sent);
    assert!(!plan.aborted);
    // отдельный ACK-пакет, первый фрагмент и одно продолжение
    assert_eq!(plan.packets.len(), 3);
    assert_eq!(
        blocks(&plan.packets[0].payload),
        vec![(Ssu2BlockType::Ack, empty_ack().to_body())]
    );
    assert_eq!(
        blocks(&plan.packets[1].payload)[0].0,
        Ssu2BlockType::FirstFragment
    );
    assert_eq!(
        blocks(&plan.packets[2].payload)[0].0,
        Ssu2BlockType::FollowOnFragment
    );
    assert_eq!(plan.packets[2].flags, 0, "двух фрагментов мало для флага");
    assert_eq!(reassemble(&plan, p.max_num_fragments()), Some(msg));
}

#[test]
fn fragmented_message_pads_and_flags_last_fragment() {
    let p = I2pdPolicy;
    // ntcp2_len = 309 -> три продолжения (номера 1, 2, 3).
    let msg = message(300);
    let mut rng = Rolls::constant(0);
    let plan = ssu2_send::fragmented_message(&msg, 100, &empty_ack(), &mut rng, &p).expect("ok");
    assert_eq!(plan.packets.len(), 5, "ACK + первый + три продолжения");
    let last = plan.packets.last().expect("last packet");
    assert_eq!(last.flags, SSU2_FLAG_IMMEDIATE_ACK_REQUESTED);
    let b = blocks(&last.payload);
    assert_eq!(
        b.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        vec![Ssu2BlockType::FollowOnFragment, Ssu2BlockType::Padding]
    );
    assert_eq!(reassemble(&plan, p.max_num_fragments()), Some(msg));
}

#[test]
fn fragmented_message_keeps_ack_in_first_fragment() {
    let p = I2pdPolicy;
    // max_payload = 20: ack (8) + 12 не меньше 20, поэтому ACK не отделяется.
    let msg = message(21); // ntcp2_len = 30
    let mut rng = Rolls::constant(0);
    let plan = ssu2_send::fragmented_message(&msg, 20, &empty_ack(), &mut rng, &p).expect("ok");
    assert!(plan.ack_block_sent);
    assert!(!plan.aborted);
    let kinds: Vec<_> = blocks(&plan.packets[0].payload)
        .iter()
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(
        kinds,
        vec![Ssu2BlockType::Ack, Ssu2BlockType::FirstFragment],
        "ACK должен уйти в начале первого фрагмента"
    );
}

#[test]
fn fragmented_message_rejects_tiny_max_payload() {
    let p = I2pdPolicy;
    let msg = message(180);
    let mut rng = Rolls::constant(0);
    let err = ssu2_send::fragmented_message(&msg, 8, &empty_ack(), &mut rng, &p)
        .expect_err("max_payload слишком мал");
    assert!(
        matches!(err, I2PError::InvalidLength { .. }),
        "unexpected {err:?}"
    );
}

#[test]
fn fragmented_message_aborts_when_first_fragment_has_no_room() {
    let p = I2pdPolicy;
    // extra_size = 100: offset = 95 оставляет первому фрагменту всего 5 байт.
    let msg = message(180);
    let mut rng = Rolls::constant(95);
    let plan = ssu2_send::fragmented_message(&msg, 100, &empty_ack(), &mut rng, &p).expect("ok");
    assert!(plan.aborted);
    assert!(!plan.ack_block_sent, "i2pd вернул бы false");
    assert_eq!(plan.packets.len(), 1, "успел уйти только ACK-пакет");
    assert_eq!(plan.packets[0].payload.len(), 8);
}

#[test]
fn fragmented_message_shifts_first_fragment_by_offset() {
    let p = I2pdPolicy;
    let msg = message(180);
    // первый offset = 50, дальше нули
    let mut rng = Rolls::sequence(vec![50, 0]);
    let plan = ssu2_send::fragmented_message(&msg, 100, &empty_ack(), &mut rng, &p).expect("ok");
    assert!(!plan.aborted);
    // первый (после ACK) пакет короче на величину смещения
    assert_eq!(plan.packets[1].payload.len(), 50);
    assert_eq!(reassemble(&plan, p.max_num_fragments()), Some(msg));
}
