@0xdd33f90089b3556f;

interface CmdLineInter {
    echo                 @0 () -> ();
    resetCounters        @1 () -> ();
    counters             @2 () -> (counts: Counters);
    setCaptureFile       @3 (filePath: Text) -> (result: SuccessOrError);
    closeCaptureFile     @4 () -> ();
    flushCaptureFile     @5 () -> ();
    setCaptureProgram    @6 (program: Program) -> (result: SuccessOrError);
    deleteCaptureProgram @7 () -> ();
    perfSample           @8 (duration_secs: UInt64, frequency_per_sec: UInt64) -> (result: Text); # Currently unsupported in PH
    showLinkSummary      @9 () -> (summary: List(Text));
    showLink             @10 (id: UInt32) -> (result: Text);
    configureLink        @11 (id: UInt32) -> (); # Currently unsupported in PH
    startLink            @12 (id: UInt32) -> (result: SuccessOrError);
    stopLink             @13 (id: UInt32) -> (result: SuccessOrError);
    resetLink            @14 (id: UInt32) -> ();
    changeLogging        @15 (logs: List(Log)) -> (result: LogsApplied);
    getNodeInfo          @16 () -> (result: SuccessOrError);
}

struct SuccessOrError {
    union {
        success @0 :SuccessValue;
        error   @1 :ErrorValue;
    }
}

struct SuccessValue {
    none @0 :Void;
    sockAddr @1 :SockAddr;
}

struct ErrorValue {
    txt @0 :Text;
}

struct LogsApplied {
    applied @0 :List(Text);
    ignored @1 :List(Text);
}

struct Counter {
    name @0 :Text;
    val  @1 :UInt64;
}

struct CounterGroup {
    id       @0 :UInt32;
    counters @1 :List(Counter);
}

struct Counters {
    management     @0 :CounterGroup;
    fastpaths      @1 :List(CounterGroup);
    uptimeSec      @2 :UInt64;
    uptimeSubsecMs @3 :UInt32;
}

struct BpfInsn {
    code @0 :UInt16;
    jt   @1 :UInt8;
    jf   @2 :UInt8;
    k    @3 :UInt32;
}

struct Log {
    level  @0 :Text;
    target @1 :Text;
}

struct Program {
    bpfProg @0 :List(BpfInsn);
}

struct IpAddr {
  union {
    v4 @0 :Data;
    v6 @1 :Data;
  }
}

struct SockAddr {
  addr @0 :IpAddr;
  port @1 :UInt16;
}