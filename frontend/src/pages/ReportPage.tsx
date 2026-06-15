import { useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import AppFrame from "../components/AppFrame";
import type { ReportSelection } from "../features/flow/ReportPanels";
import { ReportConfigPanel, ReportResultPanel } from "../features/flow/ReportPanels";
import { useScanStore } from "../store/scanStore";
import type { ScanResult } from "../types/scan";

function getDefaultReportSelection(scanResult?: ScanResult): ReportSelection {
  if (scanResult?.stack_scan) return { type: "stack" };
  if (scanResult?.endpoint_scans?.length) return { type: "endpoint", index: 0 };
  return { type: "all" };
}

function ReportPage() {
  const navigate = useNavigate();
  const common = useScanStore((state) => state.common);
  const endpointRequests = useScanStore((state) => state.endpointRequests);
  const stack = useScanStore((state) => state.stack);
  const scanResult = useScanStore((state) => state.scanResult);
  const resetAll = useScanStore((state) => state.resetAll);
  const [reportSelection, setReportSelection] = useState<{
    reportKey: string;
    value: ReportSelection;
  }>({ reportKey: "", value: { type: "all" } });
  const reportKey = scanResult
    ? [
        scanResult.stack_scan?.scan_id ?? "no-stack",
        ...(scanResult.endpoint_scans?.map((scan) => scan.scan_id) ?? ["no-endpoints"]),
      ].join("|")
    : "";
  const selectedReport =
    reportSelection.reportKey === reportKey
      ? reportSelection.value
      : getDefaultReportSelection(scanResult);
  const selectReport = (selection: ReportSelection) => {
    setReportSelection({ reportKey, value: selection });
  };

  if (!scanResult) return <Navigate replace to="/run" />;

  return (
    <AppFrame
      eyebrow="Scan Report"
      actions={
        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            onClick={() => navigate("/run")}
            className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-700"
          >
            실행으로
          </button>
          <button
            type="button"
            onClick={() => {
              resetAll();
              navigate("/setup");
            }}
            className="rounded-full border border-rose-200 bg-rose-50 px-4 py-2 text-sm text-rose-700"
          >
            처음부터
          </button>
        </div>
      }
    >
      <div className="grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
        <ReportConfigPanel
          common={common}
          endpointRequests={endpointRequests}
          endpointScans={scanResult.endpoint_scans}
          selectedReport={selectedReport}
          stack={stack}
          stackScan={scanResult.stack_scan}
          onSelectReport={selectReport}
        />
        <ReportResultPanel scanResult={scanResult} selectedReport={selectedReport} />
      </div>
    </AppFrame>
  );
}

export default ReportPage;
