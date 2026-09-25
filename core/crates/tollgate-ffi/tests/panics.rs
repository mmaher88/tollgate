use tollgate_ffi::{TollgateError, catch_panic, panic_message};

#[test]
fn a_panic_becomes_an_internal_error_with_its_message() {
    let result: Result<(), TollgateError> = catch_panic(|| panic!("boom"));
    assert_eq!(
        result,
        Err(TollgateError::Internal {
            message: "boom".to_string()
        })
    );
}

#[test]
fn a_formatted_panic_keeps_its_arguments() {
    let result: Result<u16, TollgateError> = catch_panic(|| panic!("bad packet {}", 7));
    assert_eq!(
        result,
        Err(TollgateError::Internal {
            message: "bad packet 7".to_string()
        })
    );
}

#[test]
fn a_panic_with_another_payload_gets_a_fixed_message() {
    let result: Result<(), TollgateError> = catch_panic(|| std::panic::panic_any(42_u32));
    assert_eq!(
        result,
        Err(TollgateError::Internal {
            message: "panic with a non-string payload".to_string()
        })
    );
}

#[test]
fn results_pass_through_unchanged() {
    assert_eq!(catch_panic(|| Ok(5)), Ok(5));
    assert_eq!(
        catch_panic::<()>(|| Err(TollgateError::AlreadyRunning)),
        Err(TollgateError::AlreadyRunning)
    );
}

#[test]
fn panic_message_reads_str_and_string_payloads() {
    let payload = std::panic::catch_unwind(|| panic!("plain")).unwrap_err();
    assert_eq!(panic_message(payload.as_ref()), "plain");
    let payload = std::panic::catch_unwind(|| panic!("{}-{}", "with", "args")).unwrap_err();
    assert_eq!(panic_message(payload.as_ref()), "with-args");
}

#[test]
fn errors_display_their_messages() {
    let cases = [
        (
            TollgateError::Config {
                message: "x".to_string(),
            },
            "invalid configuration: x",
        ),
        (
            TollgateError::Io {
                message: "x".to_string(),
            },
            "I/O error: x",
        ),
        (
            TollgateError::Lists {
                message: "x".to_string(),
            },
            "filter lists: x",
        ),
        (
            TollgateError::Ca {
                message: "x".to_string(),
            },
            "certificate authority: x",
        ),
        (
            TollgateError::AlreadyRunning,
            "the engine is already running",
        ),
        (
            TollgateError::Internal {
                message: "x".to_string(),
            },
            "internal error: x",
        ),
    ];
    for (error, text) in cases {
        assert_eq!(error.to_string(), text);
    }
}
