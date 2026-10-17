use std::time::Duration;
use uu_i2p::{
    i2np_message::I2npMessage,
    ssu2_block::{FirstFragmentBlock, FollowOnFragmentBlock, follow_on_frag_byte},
    ssu2_fragments::IncompleteMessages,
    ssu2_policy::SSU2_INCOMPLETE_MESSAGES_CLEANUP_TIMEOUT,
};

const MSG_ID: u32 = 0xdead_beef;
const TYPE_DATABASE_STORE: u8 = 1;
const MAX_FRAGMENTS: u8 = 64;

const T0: Duration = Duration::from_secs(1000);
const T1: Duration = Duration::from_secs(1001);

/// NTCP2-поток I2NP-сообщения: тип(1) + `msg_id`(4) + expiration(4) + payload.
fn ntcp2(type_id: u8, msg_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + payload.len());
    out.push(type_id);
    out.extend_from_slice(&msg_id.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn first_block(prefix: &[u8]) -> FirstFragmentBlock {
    FirstFragmentBlock(I2npMessage::from_ntcp2_bytes(prefix).expect("first fragment parses"))
}

fn payload(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from(i % 256).expect("mod 256 fits"))
        .collect()
}

// ---- первый фрагмент ----------------------------------------------------

#[test]
fn first_fragment_alone_is_incomplete() {
    let data = ntcp2(TYPE_DATABASE_STORE, MSG_ID, &payload(40));
    let mut msgs = IncompleteMessages::new();
    assert!(
        msgs.handle_first_fragment(&first_block(&data[..20]), T0)
            .is_none()
    );
    assert_eq!(msgs.len(), 1);
    assert!(msgs.contains(MSG_ID));
}

#[test]
fn first_then_last_completes() {
    let body = payload(100);
    let data = ntcp2(TYPE_DATABASE_STORE, MSG_ID, &body);
    let mut msgs = IncompleteMessages::new();
    assert!(
        msgs.handle_first_fragment(&first_block(&data[..30]), T0)
            .is_none()
    );

    let block = FollowOnFragmentBlock {
        frag: follow_on_frag_byte(1, true),
        msg_id: MSG_ID,
        data: &data[30..],
    };
    let msg = msgs
        .handle_follow_on_fragment(&block, T1, MAX_FRAGMENTS)
        .expect("complete");
    assert_eq!(msg.msg_id(), MSG_ID);
    assert_eq!(msg.payload(), body.as_slice());
    assert!(msgs.is_empty(), "набор должен опустеть");
}

#[test]
fn follow_on_before_first_fragment() {
    let body = payload(50);
    let data = ntcp2(TYPE_DATABASE_STORE, MSG_ID, &body);
    let mut msgs = IncompleteMessages::new();

    let block = FollowOnFragmentBlock {
        frag: follow_on_frag_byte(1, true),
        msg_id: MSG_ID,
        data: &data[20..],
    };
    assert!(
        msgs.handle_follow_on_fragment(&block, T0, MAX_FRAGMENTS)
            .is_none()
    );
    assert!(msgs.contains(MSG_ID));

    let msg = msgs
        .handle_first_fragment(&first_block(&data[..20]), T1)
        .expect("first finishes the message");
    assert_eq!(msg.payload(), body.as_slice());
    assert!(msgs.is_empty(), "набор должен опустеть");
}

#[test]
fn out_of_order_fragments_fill_later() {
    let body = payload(60);
    let data = ntcp2(TYPE_DATABASE_STORE, MSG_ID, &body);
    // Первый фрагмент: 20 байт; остаток (49) — три продолжения.
    let d1 = &data[20..40];
    let d2 = &data[40..60];
    let d3 = &data[60..];

    let mut msgs = IncompleteMessages::new();
    assert!(
        msgs.handle_first_fragment(&first_block(&data[..20]), T0)
            .is_none()
    );

    // Сразу фрагмент 2 (не последний) — уходит в отложенные.
    let f2 = FollowOnFragmentBlock {
        frag: follow_on_frag_byte(2, false),
        msg_id: MSG_ID,
        data: d2,
    };
    assert!(
        msgs.handle_follow_on_fragment(&f2, T0, MAX_FRAGMENTS)
            .is_none()
    );

    // Фрагмент 1 подтягивает фрагмент 2, но не завершает (нет 3).
    let f1 = FollowOnFragmentBlock {
        frag: follow_on_frag_byte(1, false),
        msg_id: MSG_ID,
        data: d1,
    };
    assert!(
        msgs.handle_follow_on_fragment(&f1, T0, MAX_FRAGMENTS)
            .is_none()
    );
    assert!(msgs.contains(MSG_ID));

    let f3 = FollowOnFragmentBlock {
        frag: follow_on_frag_byte(3, true),
        msg_id: MSG_ID,
        data: d3,
    };
    let msg = msgs
        .handle_follow_on_fragment(&f3, T1, MAX_FRAGMENTS)
        .expect("complete");
    assert_eq!(msg.payload(), body.as_slice());
}

#[test]
fn last_fragment_stops_concatenation() {
    let body = payload(60);
    let data = ntcp2(TYPE_DATABASE_STORE, MSG_ID, &body);
    let d1 = &data[20..40];
    let d2 = &data[40..60];
    let d3 = &data[60..];

    let mut msgs = IncompleteMessages::new();
    assert!(
        msgs.handle_first_fragment(&first_block(&data[..20]), T0)
            .is_none()
    );

    // Отложены фрагмент 2 (последний!) и лишний фрагмент 3.
    for (num, last, chunk) in [(2u8, true, d2), (3, false, d3)] {
        let f = FollowOnFragmentBlock {
            frag: follow_on_frag_byte(num, last),
            msg_id: MSG_ID,
            data: chunk,
        };
        assert!(
            msgs.handle_follow_on_fragment(&f, T0, MAX_FRAGMENTS)
                .is_none()
        );
    }

    // Фрагмент 1 склеивает 1 и 2 (последний) и завершает; фрагмент 3 отброшен.
    let f1 = FollowOnFragmentBlock {
        frag: follow_on_frag_byte(1, false),
        msg_id: MSG_ID,
        data: d1,
    };
    let msg = msgs
        .handle_follow_on_fragment(&f1, T1, MAX_FRAGMENTS)
        .expect("complete");
    assert_eq!(msg.payload(), &data[9..60]);
    assert!(msgs.is_empty(), "набор должен опустеть");
}

#[test]
fn duplicate_follow_on_is_ignored() {
    let body = payload(60);
    let data = ntcp2(TYPE_DATABASE_STORE, MSG_ID, &body);
    let d1 = &data[20..40];
    let d2 = &data[40..];

    let mut msgs = IncompleteMessages::new();
    msgs.handle_first_fragment(&first_block(&data[..20]), T0);

    let f1 = FollowOnFragmentBlock {
        frag: follow_on_frag_byte(1, false),
        msg_id: MSG_ID,
        data: d1,
    };
    assert!(
        msgs.handle_follow_on_fragment(&f1, T0, MAX_FRAGMENTS)
            .is_none()
    );
    // Повтор фрагмента 1 — уже обработан.
    assert!(
        msgs.handle_follow_on_fragment(&f1, T0, MAX_FRAGMENTS)
            .is_none()
    );

    let f2 = FollowOnFragmentBlock {
        frag: follow_on_frag_byte(2, true),
        msg_id: MSG_ID,
        data: d2,
    };
    let msg = msgs
        .handle_follow_on_fragment(&f2, T1, MAX_FRAGMENTS)
        .expect("complete");
    assert_eq!(msg.payload(), body.as_slice());
}

#[test]
fn duplicate_first_fragment_overwrites() {
    let body = payload(60);
    let data = ntcp2(TYPE_DATABASE_STORE, MSG_ID, &body);

    let mut msgs = IncompleteMessages::new();
    msgs.handle_first_fragment(&first_block(&data[..20]), T0);
    // Второй первый фрагмент (длиннее) перезаписывает накопленное.
    msgs.handle_first_fragment(&first_block(&data[..25]), T0);

    let rest = FollowOnFragmentBlock {
        frag: follow_on_frag_byte(1, true),
        msg_id: MSG_ID,
        data: &data[25..],
    };
    let msg = msgs
        .handle_follow_on_fragment(&rest, T1, MAX_FRAGMENTS)
        .expect("complete");
    assert_eq!(msg.payload(), body.as_slice());
}

// ---- границы номера фрагмента -------------------------------------------

#[test]
fn fragment_num_zero_is_rejected() {
    let mut msgs = IncompleteMessages::new();
    let block = FollowOnFragmentBlock {
        frag: follow_on_frag_byte(0, false),
        msg_id: MSG_ID,
        data: b"x",
    };
    assert!(
        msgs.handle_follow_on_fragment(&block, T0, MAX_FRAGMENTS)
            .is_none()
    );
    assert!(msgs.is_empty(), "нулевой номер не создаёт запись");
}

#[test]
fn fragment_num_at_limit_is_rejected() {
    let mut msgs = IncompleteMessages::new();
    let block = FollowOnFragmentBlock {
        frag: follow_on_frag_byte(4, true),
        msg_id: MSG_ID,
        data: b"x",
    };
    // max_num_fragments = 4 => допустимы номера 1..=3.
    assert!(msgs.handle_follow_on_fragment(&block, T0, 4).is_none());
    assert!(msgs.is_empty(), "номер на пределе не создаёт запись");
}

#[test]
fn fragment_num_below_limit_is_accepted() {
    let data = ntcp2(TYPE_DATABASE_STORE, MSG_ID, &payload(40));
    let mut msgs = IncompleteMessages::new();
    msgs.handle_first_fragment(&first_block(&data[..20]), T0);

    let block = FollowOnFragmentBlock {
        frag: follow_on_frag_byte(3, true),
        msg_id: MSG_ID,
        data: &data[20..],
    };
    // Номер 3 < 4 — принимается (уходит в отложенные, первого звена нет).
    assert!(msgs.handle_follow_on_fragment(&block, T1, 4).is_none());
    assert!(msgs.contains(MSG_ID));
}

// ---- независимость и очистка --------------------------------------------

#[test]
fn messages_are_independent() {
    let other_id = 0x1234_5678;
    let a = ntcp2(TYPE_DATABASE_STORE, MSG_ID, &payload(40));
    let b = ntcp2(TYPE_DATABASE_STORE, other_id, &payload(40));

    let mut msgs = IncompleteMessages::new();
    msgs.handle_first_fragment(&first_block(&a[..20]), T0);
    msgs.handle_first_fragment(&first_block(&b[..20]), T0);
    assert_eq!(msgs.len(), 2);

    let last_a = FollowOnFragmentBlock {
        frag: follow_on_frag_byte(1, true),
        msg_id: MSG_ID,
        data: &a[20..],
    };
    let msg = msgs
        .handle_follow_on_fragment(&last_a, T1, MAX_FRAGMENTS)
        .expect("A complete");
    assert_eq!(msg.msg_id(), MSG_ID);
    assert_eq!(msgs.len(), 1);
    assert!(msgs.contains(other_id));
}

#[test]
fn cleanup_removes_stale_only() {
    let timeout = SSU2_INCOMPLETE_MESSAGES_CLEANUP_TIMEOUT;
    let data = ntcp2(TYPE_DATABASE_STORE, MSG_ID, &payload(40));
    let mut msgs = IncompleteMessages::new();
    msgs.handle_first_fragment(&first_block(&data[..20]), T0);

    msgs.cleanup(T0 + timeout, timeout);
    assert!(msgs.contains(MSG_ID), "на границе ещё живой");

    msgs.cleanup(T0 + timeout + Duration::from_millis(1), timeout);
    assert!(msgs.is_empty(), "просроченный удалён");
}

#[test]
fn default_policy_timeout_is_thirty_seconds() {
    assert_eq!(
        SSU2_INCOMPLETE_MESSAGES_CLEANUP_TIMEOUT,
        Duration::from_secs(30)
    );
}
