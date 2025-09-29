@0xdd33f90089b3556f;

interface CmdLineInter {
    echo @0 () -> ();
    resetCounters @1 () -> ();
    counters @2 () -> (counts: Text);
    setCaptureFile @3 (filePath: Text) -> ();
    closeCaptureFile @4 () -> ();
    flushCaptureFile @5 () -> ();
    setCaptureProgram @6 (program: Text) -> ();
    deleteCaptureProgram @7 () -> ();
    perfSample @8 (duration: UInt64, frequency: UInt64) -> (result: Text);
    showLinkSummary @9 () -> (summary: Text);
    showLink @10 (id: UInt32) -> (result: Text);
    configureLink @11 (id: UInt32) -> (result: Text);
    startLink @12 (id: UInt32) -> (result: Text);
    stopLink @13 (id: UInt32) -> (restult: Text);
    resetLink @14 (id: UInt32) -> ();
    changeLogging @15 (logs: Text) -> ();
}