//! Serialized lifecycle decisions. Events are trusted coordinator acknowledgements,
//! never user/IPC input. This module does not perform their claimed effects.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Queued,
    Probing,
    Downloading,
    Pausing,
    Paused,
    RetryWait,
    NeedsAction,
    Verifying,
    Publishing,
    Cancelling,
    Cancelled,
    Recovering,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Start,
    Pause,
    Resume,
    Retry,
    Cancel,
    Recover,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    ProbeSucceeded,
    TransferFinished,
    Verified,
    PublishSucceeded,
    WorkersStopped,
    /// All workers stopped; no outstanding writes or publication effects.
    RetryableFailureAfterStop,
    /// All workers stopped; publication outcome reconciled if applicable.
    ActionRequiredAfterStop,
    /// Disk reconciliation finished; remain paused, never assume completion.
    Reconciled,
}

/// Nonsecret identity assigned by the owner. The owner must never reuse an ID
/// while any event for its previous instance could still arrive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DownloadId(pub u128);

/// Opaque, process-local attempt identity bound to one download. Not authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptToken {
    download_id: DownloadId,
    sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionError {
    IllegalTransition,
    StaleAttempt,
    AttemptExhausted,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Download {
    state: State,
    attempt: AttemptToken,
}

impl Download {
    pub fn new(id: DownloadId) -> Self {
        Self {
            state: State::Queued,
            attempt: AttemptToken {
                download_id: id,
                sequence: 0,
            },
        }
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn attempt(&self) -> AttemptToken {
        self.attempt
    }

    /// The owner serializes commands and events. Failed operations leave state intact.
    /// Recover is permitted only after the coordinator has stopped all old workers.
    pub fn command(&mut self, command: Command) -> Result<State, TransitionError> {
        use Command as C;
        use State as S;
        let (next, new_attempt) = match (self.state, command) {
            (S::Queued, C::Start) => (S::Probing, true),
            (S::Paused | S::NeedsAction, C::Resume) => (S::Probing, true),
            (S::RetryWait, C::Retry) => (S::Probing, true),
            (S::Probing | S::Downloading | S::Verifying, C::Pause) => (S::Pausing, false),
            (S::Queued | S::RetryWait | S::NeedsAction, C::Pause) => (S::Paused, false),
            (S::Probing | S::Downloading | S::Verifying | S::Pausing, C::Cancel) => {
                (S::Cancelling, false)
            }
            (S::Queued | S::Paused | S::RetryWait | S::NeedsAction, C::Cancel) => {
                (S::Cancelled, false)
            }
            (S::Completed | S::Cancelled | S::Recovering, C::Recover) => {
                return Err(TransitionError::IllegalTransition)
            }
            (_, C::Recover) => (S::Recovering, true),
            _ => return Err(TransitionError::IllegalTransition),
        };
        let attempt = if new_attempt {
            AttemptToken {
                download_id: self.attempt.download_id,
                sequence: self
                    .attempt
                    .sequence
                    .checked_add(1)
                    .ok_or(TransitionError::AttemptExhausted)?,
            }
        } else {
            self.attempt
        };
        self.state = next;
        self.attempt = attempt;
        Ok(next)
    }

    pub fn event(&mut self, attempt: AttemptToken, event: Event) -> Result<State, TransitionError> {
        if attempt != self.attempt {
            return Err(TransitionError::StaleAttempt);
        }
        use Event as E;
        use State as S;
        let next = match (self.state, event) {
            (S::Probing, E::ProbeSucceeded) => S::Downloading,
            (S::Downloading, E::TransferFinished) => S::Verifying,
            (S::Verifying, E::Verified) => S::Publishing,
            (S::Publishing, E::PublishSucceeded) => S::Completed,
            (S::Pausing, E::WorkersStopped) => S::Paused,
            (S::Cancelling, E::WorkersStopped) => S::Cancelled,
            (S::Probing | S::Downloading | S::Verifying, E::RetryableFailureAfterStop) => {
                S::RetryWait
            }
            (
                S::Probing | S::Downloading | S::Verifying | S::Publishing | S::Recovering,
                E::ActionRequiredAfterStop,
            ) => S::NeedsAction,
            (S::Recovering, E::Reconciled) => S::Paused,
            _ => return Err(TransitionError::IllegalTransition),
        };
        self.state = next;
        Ok(next)
    }
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::IllegalTransition => "operation is not allowed in current state",
            Self::StaleAttempt => "event belongs to another download or an obsolete attempt",
            Self::AttemptExhausted => "attempt counter exhausted",
        })
    }
}
impl std::error::Error for TransitionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn downloading() -> Download {
        let mut job = Download::new(DownloadId(1));
        job.command(Command::Start).unwrap();
        job.event(job.attempt(), Event::ProbeSucceeded).unwrap();
        job
    }

    #[test]
    fn completion_requires_verification_then_publication_acknowledgement() {
        let mut job = downloading();
        let token = job.attempt();
        assert_eq!(
            job.event(token, Event::PublishSucceeded),
            Err(TransitionError::IllegalTransition)
        );
        assert_eq!(
            job.event(token, Event::Verified),
            Err(TransitionError::IllegalTransition)
        );
        job.event(token, Event::TransferFinished).unwrap();
        assert_eq!(
            job.event(token, Event::PublishSucceeded),
            Err(TransitionError::IllegalTransition)
        );
        job.event(token, Event::Verified).unwrap();
        assert_eq!(job.state(), State::Publishing);
        assert_eq!(
            job.command(Command::Cancel),
            Err(TransitionError::IllegalTransition)
        );
        job.event(token, Event::PublishSucceeded).unwrap();
        assert_eq!(job.state(), State::Completed);
    }

    #[test]
    fn pause_and_cancel_wait_for_workers_and_ignore_late_progress() {
        for cancel in [false, true] {
            let mut job = downloading();
            let token = job.attempt();
            job.command(Command::Pause).unwrap();
            if cancel {
                job.command(Command::Cancel).unwrap();
            }
            assert_eq!(
                job.event(token, Event::TransferFinished),
                Err(TransitionError::IllegalTransition)
            );
            assert_eq!(
                job.command(Command::Resume),
                Err(TransitionError::IllegalTransition)
            );
            job.event(token, Event::WorkersStopped).unwrap();
            assert_eq!(
                job.state(),
                if cancel {
                    State::Cancelled
                } else {
                    State::Paused
                }
            );
        }
    }

    #[test]
    fn old_attempt_events_cannot_advance_restarted_download() {
        let mut job = downloading();
        let old = job.attempt();
        job.event(old, Event::RetryableFailureAfterStop).unwrap();
        job.command(Command::Retry).unwrap();
        assert_eq!(
            job.event(old, Event::ProbeSucceeded),
            Err(TransitionError::StaleAttempt)
        );
        assert_eq!(job.state(), State::Probing);
        job.event(job.attempt(), Event::ProbeSucceeded).unwrap();
        assert_eq!(
            job.event(old, Event::TransferFinished),
            Err(TransitionError::StaleAttempt)
        );
    }

    #[test]
    fn recovery_does_not_reuse_verified_or_published_claims() {
        let mut job = downloading();
        let old = job.attempt();
        job.event(old, Event::TransferFinished).unwrap();
        job.event(old, Event::Verified).unwrap();
        job.command(Command::Recover).unwrap();
        assert_eq!(
            job.event(old, Event::PublishSucceeded),
            Err(TransitionError::StaleAttempt)
        );
        assert_eq!(
            job.event(job.attempt(), Event::PublishSucceeded),
            Err(TransitionError::IllegalTransition)
        );
        job.event(job.attempt(), Event::Reconciled).unwrap();
        assert_eq!(job.state(), State::Paused);
        job.command(Command::Resume).unwrap();
        assert_eq!(job.state(), State::Probing);
    }

    #[test]
    fn terminal_states_reject_every_command_and_event() {
        for state in [State::Cancelled, State::Completed] {
            let mut job = Download {
                state,
                attempt: AttemptToken {
                    download_id: DownloadId(1),
                    sequence: 9,
                },
            };
            for command in [
                Command::Start,
                Command::Pause,
                Command::Resume,
                Command::Retry,
                Command::Cancel,
                Command::Recover,
            ] {
                assert_eq!(
                    job.command(command),
                    Err(TransitionError::IllegalTransition)
                );
                assert_eq!(job.state(), state);
            }
            for event in [
                Event::ProbeSucceeded,
                Event::TransferFinished,
                Event::Verified,
                Event::PublishSucceeded,
                Event::WorkersStopped,
                Event::RetryableFailureAfterStop,
                Event::ActionRequiredAfterStop,
                Event::Reconciled,
            ] {
                assert_eq!(
                    job.event(job.attempt(), event),
                    Err(TransitionError::IllegalTransition)
                );
                assert_eq!(job.state(), state);
            }
        }
    }

    #[test]
    fn counter_exhaustion_is_fail_closed_and_atomic() {
        let mut job = Download {
            state: State::Paused,
            attempt: AttemptToken {
                download_id: DownloadId(1),
                sequence: u64::MAX,
            },
        };
        assert_eq!(
            job.command(Command::Resume),
            Err(TransitionError::AttemptExhausted)
        );
        assert_eq!(job.state(), State::Paused);
        assert_eq!(
            job.attempt(),
            AttemptToken {
                download_id: DownloadId(1),
                sequence: u64::MAX
            }
        );
    }

    #[test]
    fn another_download_cannot_advance_matching_attempt_number() {
        let mut first = Download::new(DownloadId(1));
        let mut second = Download::new(DownloadId(2));
        first.command(Command::Start).unwrap();
        second.command(Command::Start).unwrap();
        assert_eq!(first.attempt().sequence, second.attempt().sequence);
        assert_eq!(
            second.event(first.attempt(), Event::ProbeSucceeded),
            Err(TransitionError::StaleAttempt)
        );
        assert_eq!(second.state(), State::Probing);
        second
            .event(second.attempt(), Event::ProbeSucceeded)
            .unwrap();
        first.event(first.attempt(), Event::ProbeSucceeded).unwrap();
        first
            .event(first.attempt(), Event::TransferFinished)
            .unwrap();
        second
            .event(second.attempt(), Event::TransferFinished)
            .unwrap();
        assert_eq!(
            second.event(first.attempt(), Event::Verified),
            Err(TransitionError::StaleAttempt)
        );
        assert_eq!(second.state(), State::Verifying);
    }
}
