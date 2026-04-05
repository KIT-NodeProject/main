import { useEffect, useMemo, useRef, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import AppFrame from "../components/AppFrame";
import RunExecutionPanel from "../features/flow/RunExecutionPanel";
import RunOverview from "../features/flow/RunOverview";
import {
  buildAdapterPayload,
  buildTargetRunPayload,
  normalizeEndpoint,
  serializeEndpointRequest,
} from "../lib/request";
import { useScanStore } from "../store/scanStore";
import type { ScanResult } from "../types/scan";

function RunPage() {
  const navigate = useNavigate();
  const common = useScanStore((state) => state.common);
  const endpointRequests = useScanStore((state) => state.endpointRequests);
  const stack = useScanStore((state) => state.stack);
  const setScanResult = useScanStore((state) => state.setScanResult);
  const isSubmitting = useScanStore((state) => state.isSubmitting);
  const setSubmitting = useScanStore((state) => state.setSubmitting);
  const [errorMessage, setErrorMessage] = useState("");
  const [started, setStarted] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [activeStepIndex, setActiveStepIndex] = useState(0);
  const progressTimer = useRef<number | null>(null);

  const targetPayload = useMemo(
    () =>
      buildTargetRunPayload({
        common,
        targets: { endpointEnabled: true, stackEnabled: true },
        endpoint_scan: { enabled: true, requests: endpointRequests.map(serializeEndpointRequest) },
        stack_scan: { enabled: true, stack_name: stack.stackName.trim() },
      }),
    [common, endpointRequests, stack],
  );
  const adapterPayload = useMemo(() => buildAdapterPayload(targetPayload), [targetPayload]);
  const runSteps = useMemo(
    () =>
      [
        { id: "run", label: "scan_run 생성", description: "실행 요청을 생성하고 대상 정보를 고정합니다." },
        { id: "endpoint", label: "엔드포인트 분석", description: `${endpointRequests.length}개 요청 설정을 기준으로 검사 대상을 준비합니다.` },
        { id: "stack", label: "기술 스택 분석", description: `${stack.stackName || "stack_name"} 기준으로 스택 검사를 준비합니다.` },
        { id: "report", label: "결과 정리", description: "실행 결과를 취합하고 리포트 화면으로 이동합니다." },
      ],
    [endpointRequests.length, stack.stackName],
  );

  useEffect(
    () => () => {
      if (progressTimer.current) {
        window.clearInterval(progressTimer.current);
      }
    },
    [],
  );

  if (!common.baseUrl.trim()) return <Navigate replace to="/setup" />;

  const validate = () => {
    for (const [index, request] of endpointRequests.entries()) {
      const result = normalizeEndpoint(common.baseUrl, request.path);
      if (!result.isValid) return `엔드포인트 ${index + 1}: ${result.message}`;
    }
    if (!stack.stackName.trim()) return "현재 백엔드 어댑터는 stack_name이 필요합니다.";
    return "";
  };

  const handleExecute = async () => {
    const validationMessage = validate();
    if (validationMessage) return setErrorMessage(validationMessage);
    setSubmitting(true);
    setErrorMessage("");
    setStarted(true);
    setCompleted(false);
    setActiveStepIndex(0);
    if (progressTimer.current) {
      window.clearInterval(progressTimer.current);
    }
    progressTimer.current = window.setInterval(() => {
      setActiveStepIndex((prev) => (prev < runSteps.length - 1 ? prev + 1 : prev));
    }, 900);
    try {
      const response = await fetch("/api/v1/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(adapterPayload),
      });
      if (!response.ok) throw new Error((await response.text()) || "스캔 요청에 실패했습니다.");
      setScanResult((await response.json()) as ScanResult);
      if (progressTimer.current) {
        window.clearInterval(progressTimer.current);
      }
      setActiveStepIndex(runSteps.length);
      setCompleted(true);
      window.setTimeout(() => navigate("/report"), 900);
    } catch (error) {
      if (progressTimer.current) {
        window.clearInterval(progressTimer.current);
      }
      setErrorMessage(error instanceof Error ? error.message : "백엔드 요청 중 오류가 발생했습니다.");
      setStarted(false);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AppFrame eyebrow="Run Request">
      <div className="space-y-6">
        <RunOverview common={common} stack={stack} endpointCount={endpointRequests.length} />
        <RunExecutionPanel
          steps={runSteps}
          activeIndex={activeStepIndex}
          started={started}
          completed={completed}
          isSubmitting={isSubmitting}
          errorMessage={errorMessage}
          onExecute={handleExecute}
        />
        <div className="flex justify-start">
          <button type="button" onClick={() => navigate("/endpoint")} className="rounded-full border border-slate-200 bg-white px-5 py-3 text-sm font-semibold text-slate-700">이전</button>
        </div>
      </div>
    </AppFrame>
  );
}

export default RunPage;
