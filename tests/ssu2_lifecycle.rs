use uu_i2p::ssu2_block::Ssu2TerminationReason;
use uu_i2p::ssu2_lifecycle::{SessionLifecycle, Ssu2SessionState, TerminationPlan};

#[test]
fn new_lifecycle_is_unknown_normal_close() {
    let l = SessionLifecycle::new();
    assert_eq!(l.state(), Ssu2SessionState::Unknown);
    assert_eq!(l.termination_reason(), Ssu2TerminationReason::NormalClose);
    assert!(!l.is_established());
    assert!(!l.is_terminated());
}

#[test]
fn set_state_returns_previous() {
    let mut l = SessionLifecycle::new();
    assert_eq!(
        l.set_state(Ssu2SessionState::SessionRequestSent),
        Ssu2SessionState::Unknown
    );
    assert_eq!(l.state(), Ssu2SessionState::SessionRequestSent);
    assert_eq!(
        l.set_state(Ssu2SessionState::SessionCreatedReceived),
        Ssu2SessionState::SessionRequestSent
    );
}

#[test]
fn establish_is_idempotent() {
    let mut l = SessionLifecycle::new();
    assert!(l.establish());
    assert!(l.is_established());
    assert!(!l.establish());
    assert!(l.is_established());
}

#[test]
fn request_termination_when_established_sends_termination() {
    let mut l = SessionLifecycle::new();
    l.establish();
    let plan = l.request_termination(Ssu2TerminationReason::IdleTimeout);
    assert_eq!(
        plan,
        TerminationPlan {
            send_termination: true,
            terminate_now: false,
        }
    );
    assert_eq!(l.state(), Ssu2SessionState::Closing);
    assert_eq!(l.termination_reason(), Ssu2TerminationReason::IdleTimeout);
}

#[test]
fn request_termination_when_closing_reresends() {
    let mut l = SessionLifecycle::new();
    l.establish();
    let _ = l.request_termination(Ssu2TerminationReason::IdleTimeout);
    let plan = l.request_termination(Ssu2TerminationReason::Timeout);
    assert!(plan.send_termination);
    assert_eq!(l.termination_reason(), Ssu2TerminationReason::Timeout);
}

#[test]
fn request_termination_otherwise_terminates_now() {
    let mut l = SessionLifecycle::new();
    l.set_state(Ssu2SessionState::SessionCreatedSent);
    let plan = l.request_termination(Ssu2TerminationReason::BadToken);
    assert_eq!(
        plan,
        TerminationPlan {
            send_termination: false,
            terminate_now: true,
        }
    );
    // i2pd до `Done ()` состояние не меняет — его сменит `Terminate`.
    assert_eq!(l.state(), Ssu2SessionState::SessionCreatedSent);
    assert_eq!(l.termination_reason(), Ssu2TerminationReason::NormalClose);
}

#[test]
fn reset_termination_reason() {
    let mut l = SessionLifecycle::new();
    l.establish();
    let _ = l.request_termination(Ssu2TerminationReason::ClockSkew);
    assert_eq!(l.termination_reason(), Ssu2TerminationReason::ClockSkew);
    l.reset_termination_reason();
    assert_eq!(l.termination_reason(), Ssu2TerminationReason::NormalClose);
}

#[test]
fn terminate_only_first_time() {
    let mut l = SessionLifecycle::new();
    l.establish();
    assert!(l.terminate());
    assert_eq!(l.state(), Ssu2SessionState::Terminated);
    assert!(l.is_terminated());
    assert!(!l.terminate());
}

#[test]
fn failed_counts_as_terminated() {
    let mut l = SessionLifecycle::new();
    l.set_state(Ssu2SessionState::Failed);
    assert!(l.is_terminated());
    assert!(!l.is_established());
    // `Failed` -> `Terminate` всё ещё «впервые».
    assert!(l.terminate());
}

#[test]
fn state_classification_and_names() {
    use Ssu2SessionState as S;
    assert!(S::Established.is_established());
    assert!(!S::Closing.is_established());
    assert!(S::SessionRequestSent.is_handshake());
    assert!(S::TokenRequestReceived.is_handshake());
    assert!(!S::Established.is_handshake());
    assert!(S::Terminated.is_terminated());
    assert!(S::Failed.is_terminated());
    assert!(!S::Closing.is_terminated());
    assert_eq!(S::SessionConfirmedSent.name(), "SessionConfirmedSent");
    assert_eq!(S::default(), S::Unknown);
}
