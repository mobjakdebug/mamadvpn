//! # TCP Connection State Machine
//!
//! Models the TCP connection lifecycle as tracked by the bypass injector.
//! This directly mirrors the implicit state machine in the Python
//! `fake_tcp.py` / `monitor_connection.py` files.

use std::fmt;

use crate::connection::ConnectionEvent;

/// State of a single tracked TCP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state — no packets seen yet.
    Initial,

    /// Outbound SYN was sent; we know the client's initial sequence number.
    SynSent {
        syn_seq: u32,
    },

    /// Inbound SYN-ACK was received and validated against the SYN.
    SynAckReceived {
        syn_seq: u32,
        syn_ack_seq: u32,
    },

    /// Outbound ACK completing the three-way handshake was sent.
    AckSent {
        syn_seq: u32,
        syn_ack_seq: u32,
    },

    /// Fake data has been injected with a manipulated sequence number.
    FakeSent {
        syn_seq: u32,
        syn_ack_seq: u32,
    },

    /// The remote server has ACKed the fake data.
    FakeAcked {
        syn_seq: u32,
        syn_ack_seq: u32,
    },

    /// Connection is in relay mode — bidirectional forwarding active.
    Relaying,

    /// Connection has been closed or encountered an error.
    Closed,
}

impl ConnectionState {
    /// Returns `true` if the connection is still being tracked (not closed).
    pub fn is_alive(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// Returns `true` if the bypass sequence has completed and relay can start.
    pub fn can_relay(&self) -> bool {
        matches!(self, Self::FakeAcked { .. } | Self::Relaying)
    }

    /// Apply an event to the state machine, returning the new state.
    pub fn transition(self, event: &ConnectionEvent) -> Result<Self, UnexpectedEvent> {
        match (&self, event) {
            // ---- Initial -> SynSent ----
            (Self::Initial, ConnectionEvent::OutboundSyn { seq }) => {
                Ok(Self::SynSent { syn_seq: *seq })
            }

            // ---- SynSent -> SynAckReceived (validate ack_num) ----
            (
                Self::SynSent { syn_seq },
                ConnectionEvent::InboundSynAck { seq, ack },
            ) => {
                let expected_ack = syn_seq.wrapping_add(1);
                if *ack != expected_ack {
                    return Err(UnexpectedEvent::new(
                        &self,
                        event,
                        format!(
                            "SYN-ACK ack_num {ack} != expected {expected_ack} (syn_seq+1)"
                        ),
                    ));
                }
                Ok(Self::SynAckReceived {
                    syn_seq: *syn_seq,
                    syn_ack_seq: *seq,
                })
            }

            // ---- SynAckReceived -> AckSent (validate seq and ack) ----
            (
                Self::SynAckReceived {
                    syn_seq,
                    syn_ack_seq,
                },
                ConnectionEvent::OutboundAck { seq, ack },
            ) => {
                let expected_seq = syn_seq.wrapping_add(1);
                let expected_ack = syn_ack_seq.wrapping_add(1);
                if *seq != expected_seq {
                    return Err(UnexpectedEvent::new(
                        &self,
                        event,
                        format!("ACK seq_num {seq} != expected {expected_seq}"),
                    ));
                }
                if *ack != expected_ack {
                    return Err(UnexpectedEvent::new(
                        &self,
                        event,
                        format!("ACK ack_num {ack} != expected {expected_ack}"),
                    ));
                }
                Ok(Self::AckSent {
                    syn_seq: *syn_seq,
                    syn_ack_seq: *syn_ack_seq,
                })
            }

            // ---- AckSent -> FakeSent (after injection) ----
            (Self::AckSent { syn_seq, syn_ack_seq }, ConnectionEvent::FakeDataInjected) => {
                Ok(Self::FakeSent {
                    syn_seq: *syn_seq,
                    syn_ack_seq: *syn_ack_seq,
                })
            }

            // ---- FakeSent -> FakeAcked (validate incoming ACK) ----
            (
                Self::FakeSent {
                    syn_seq,
                    syn_ack_seq,
                },
                ConnectionEvent::InboundAck { seq, ack },
            ) => {
                let expected_seq = syn_ack_seq.wrapping_add(1);
                let expected_ack = syn_seq.wrapping_add(1);
                if *seq != expected_seq {
                    return Err(UnexpectedEvent::new(
                        &self,
                        event,
                        format!("FAKE-ACK seq_num {seq} != expected {expected_seq}"),
                    ));
                }
                if *ack != expected_ack {
                    return Err(UnexpectedEvent::new(
                        &self,
                        event,
                        format!("FAKE-ACK ack_num {ack} != expected {expected_ack}"),
                    ));
                }
                Ok(Self::FakeAcked {
                    syn_seq: *syn_seq,
                    syn_ack_seq: *syn_ack_seq,
                })
            }

            // ---- FakeAcked -> Relaying ----
            (Self::FakeAcked { syn_seq, syn_ack_seq }, ConnectionEvent::StartRelay) => {
                Ok(Self::Relaying)
            }

            // ---- Any -> Closed ----
            (_, ConnectionEvent::Close) | (_, ConnectionEvent::Error(_)) => Ok(Self::Closed),

            // ---- Relaying -> Closed ----
            (Self::Relaying, ConnectionEvent::Close) | (Self::Relaying, ConnectionEvent::Error(_)) => {
                Ok(Self::Closed)
            }

            // ---- Any other transition is unexpected ----
            _ => Err(UnexpectedEvent::new(
                &self,
                event,
                format!("No transition defined from {self:?} for event {event:?}"),
            )),
        }
    }
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::Initial
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initial => write!(f, "Initial"),
            Self::SynSent { .. } => write!(f, "SynSent"),
            Self::SynAckReceived { .. } => write!(f, "SynAckReceived"),
            Self::AckSent { .. } => write!(f, "AckSent"),
            Self::FakeSent { .. } => write!(f, "FakeSent"),
            Self::FakeAcked { .. } => write!(f, "FakeAcked"),
            Self::Relaying => write!(f, "Relaying"),
            Self::Closed => write!(f, "Closed"),
        }
    }
}

/// Indicates a packet arrived that did not match the expected state machine
/// transition.  Mirrors Python's `on_unexpected_packet()`.
#[derive(Debug, Clone)]
pub struct UnexpectedEvent {
    pub from_state: String,
    pub event: String,
    pub reason: String,
}

impl UnexpectedEvent {
    fn new(state: &ConnectionState, event: &ConnectionEvent, reason: String) -> Self {
        Self {
            from_state: state.to_string(),
            event: format!("{event:?}"),
            reason,
        }
    }
}

impl fmt::Display for UnexpectedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Unexpected event '{}' in state '{}': {}",
            self.event, self.from_state, self.reason
        )
    }
}

impl std::error::Error for UnexpectedEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::ConnectionEvent;

    #[test]
    fn test_happy_path_wrong_seq() {
        let state = ConnectionState::Initial;

        let state = state.transition(&ConnectionEvent::OutboundSyn { seq: 1000 }).unwrap();
        assert_eq!(state, ConnectionState::SynSent { syn_seq: 1000 });

        let state = state
            .transition(&ConnectionEvent::InboundSynAck { seq: 5000, ack: 1001 })
            .unwrap();
        assert_eq!(state, ConnectionState::SynAckReceived { syn_seq: 1000, syn_ack_seq: 5000 });

        let state = state
            .transition(&ConnectionEvent::OutboundAck { seq: 1001, ack: 5001 })
            .unwrap();
        assert_eq!(state, ConnectionState::AckSent { syn_seq: 1000, syn_ack_seq: 5000 });

        let state = state.transition(&ConnectionEvent::FakeDataInjected).unwrap();
        assert_eq!(state, ConnectionState::FakeSent { syn_seq: 1000, syn_ack_seq: 5000 });

        let state = state
            .transition(&ConnectionEvent::InboundAck { seq: 5001, ack: 1001 })
            .unwrap();
        assert_eq!(state, ConnectionState::FakeAcked { syn_seq: 1000, syn_ack_seq: 5000 });

        let state = state.transition(&ConnectionEvent::StartRelay).unwrap();
        assert_eq!(state, ConnectionState::Relaying);

        let state = state.transition(&ConnectionEvent::Close).unwrap();
        assert_eq!(state, ConnectionState::Closed);
    }

    #[test]
    fn test_unexpected_syn_ack_ack_num() {
        let state = ConnectionState::Initial
            .transition(&ConnectionEvent::OutboundSyn { seq: 1000 })
            .unwrap();
        let result = state.transition(&ConnectionEvent::InboundSynAck { seq: 5000, ack: 9999 });
        assert!(result.is_err());
    }

    #[test]
    fn test_unexpected_inbound_before_syn() {
        let result = ConnectionState::Initial
            .transition(&ConnectionEvent::InboundSynAck { seq: 5000, ack: 1 });
        assert!(result.is_err());
    }

    #[test]
    fn test_fake_acked_to_relaying() {
        let state = ConnectionState::FakeAcked { syn_seq: 1000, syn_ack_seq: 5000 };
        let state = state.transition(&ConnectionEvent::StartRelay).unwrap();
        assert_eq!(state, ConnectionState::Relaying);
    }
}
