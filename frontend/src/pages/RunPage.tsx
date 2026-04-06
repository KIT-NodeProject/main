import { useEffect, useMemo, useRef, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import AppFrame from "../components/AppFrame";
import RunExecutionPanel from "../features/flow/RunExecutionPanel";
import RunOverview from "../features/flow/RunOverview";
import { normalizeEndpoint, serializeEndpointRequest } from "../lib/request";
import { useScanStore } from "../store/scanStore";
import type { EndpointScanResponse, ScanResult, StackScanResponse } from "../types/scan";

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

  const configuredEndpointRequests = useMemo(
    () => endpointRequests.filter((request) => request.path.trim()),
    [endpointRequests],
  );
  const hasEndpointScan = configuredEndpointRequests.length > 0;
  const hasStackScan = Boolean(stack.stackName.trim());

  const runSteps = useMemo(() => {
    const steps = [{ id: "run", label: "실행 준비", description: "입력값을 확인하고 실행 요청을 준비합니다." }];

    if (hasEndpointScan) {
      steps.push({
        id: "endpoint",
        label: "엔드포인트 분석",
        description: `${configuredEndpointRequests.length}개 요청 설정을 기준으로 응답을 확인합니다.`,
      });
    }

    if (hasStackScan) {
      steps.push({
        id: "stack",
        label: "기술 스택 분석",
        description: `${stack.stackName.trim()} 기준으로 스택 검사를 실행합니다.`,
      });
    }

    steps.push({ id: "report", label: "결과 정리", description: "실행 결과를 취합하고 리포트 화면으로 이동합니다." });
    return steps;
  }, [configuredEndpointRequests.length, hasEndpointScan, hasStackScan, stack.stackName]);

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
    if (!hasEndpointScan && !hasStackScan) {
      return "스택 이름을 입력하거나 엔드포인트 경로를 하나 이상 입력해야 합니다.";
    }

    for (const [index, request] of configuredEndpointRequests.entries()) {
      const result = normalizeEndpoint(common.baseUrl, request.path);
      if (!result.isValid) return `엔드포인트 ${index + 1}: ${result.message}`;
    }

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
      const executedTargets: Array<"stack" | "endpoint"> = [];
      const nextResult: ScanResult = { executed_targets: executedTargets };

      if (hasEndpointScan) {
        const endpointResponse = await fetch("/api/v1/endpoints/scans", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            base_url: common.baseUrl.trim(),
            endpoints: configuredEndpointRequests.map(serializeEndpointRequest),
          }),
        });

        if (!endpointResponse.ok) {
          throw new Error((await endpointResponse.text()) || "엔드포인트 스캔 요청에 실패했습니다.");
        }

        nextResult.endpoint_scan = (await endpointResponse.json()) as EndpointScanResponse;
        executedTargets.push("endpoint");
      }

      if (hasStackScan) {
        const stackResponse = await fetch("/api/v1/stack/scans", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            base_url: common.baseUrl.trim(),
            stack_name: stack.stackName.trim(),
          }),
        });

        if (!stackResponse.ok) {
          throw new Error((await stackResponse.text()) || "스택 스캔 요청에 실패했습니다.");
        }

        nextResult.stack_scan = (await stackResponse.json()) as StackScanResponse;
        executedTargets.push("stack");
      }

      setScanResult(nextResult);
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
        <RunOverview
          common={common}
          stack={stack}
          endpointCount={configuredEndpointRequests.length}
          hasEndpointScan={hasEndpointScan}
          hasStackScan={hasStackScan}
        />
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
          <button
            type="button"
            onClick={() => navigate("/endpoint")}
            className="rounded-full border border-slate-200 bg-white px-5 py-3 text-sm font-semibold text-slate-700"
          >
            이전
          </button>
        </div>
      </div>
    </AppFrame>
  );
}

export default RunPage;
