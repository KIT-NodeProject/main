import { useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import AppFrame from "../components/AppFrame";
import type { EndpointReportSelection } from "../features/flow/ReportPanels";
import { ReportConfigPanel, ReportResultPanel } from "../features/flow/ReportPanels";
import { useScanStore } from "../store/scanStore";

function ReportPage() {
  const navigate = useNavigate();
  const common = useScanStore((state) => state.common);
  const endpointRequests = useScanStore((state) => state.endpointRequests);
  const stack = useScanStore((state) => state.stack);
  const scanResult = useScanStore((state) => state.scanResult);
  const resetAll = useScanStore((state) => state.resetAll);
  const [endpointSelection, setEndpointSelection] = useState<{
    reportKey: string;
    value: EndpointReportSelection;
  }>({ reportKey: "", value: 0 });
  const endpointReportKey = scanResult?.endpoint_scans?.map((scan) => scan.scan_id).join("|") ?? "";
  const selectedEndpointIndex =
    endpointSelection.reportKey === endpointReportKey
      ? endpointSelection.value
      : endpointReportKey
        ? 0
        : "all";
  const selectEndpoint = (selection: EndpointReportSelection) => {
    setEndpointSelection({ reportKey: endpointReportKey, value: selection });
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
          selectedEndpointIndex={selectedEndpointIndex}
          stack={stack}
          onSelectEndpoint={selectEndpoint}
        />
        <ReportResultPanel
          scanResult={scanResult}
          selectedEndpointIndex={selectedEndpointIndex}
        />
      </div>
    </AppFrame>
  );
}

export default ReportPage;
