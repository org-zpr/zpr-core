@0xdd33f90089b3556f;

# I considered making success also take text, for future extensibility, but
# none of the current commands need info on success
struct SuccessOrError {
    union {
        success @0 :Void;
        error @1 :Text;
    }
}

interface CmdLineInter {
    echo @0 () -> ();
    resetCounters @1 () -> ();
    counters @2 () -> (counts: Text);
    setCaptureFile @3 (filePath: Text) -> (result: SuccessOrError);
    closeCaptureFile @4 () -> ();
    flushCaptureFile @5 () -> ();
    setCaptureProgram @6 (program: Text) -> (result: SuccessOrError);
    deleteCaptureProgram @7 () -> ();
    perfSample @8 (duration: UInt64, frequency: UInt64) -> (result: Text);
    showLinkSummary @9 () -> (summary: Text);
    showLink @10 (id: UInt32) -> (result: Text);
    configureLink @11 (id: UInt32) -> (); # Currently unsupported in PH
    startLink @12 (id: UInt32) -> (result: SuccessOrError);
    stopLink @13 (id: UInt32) -> (restult: SuccessOrError);
    resetLink @14 (id: UInt32) -> ();
    changeLogging @15 (logs: Text) -> (result: SuccessOrError);
}