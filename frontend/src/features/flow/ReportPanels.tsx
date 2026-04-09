import { composeRequestUrl, methodTone } from "../../lib/request";
import type {
  CommonConfig,
  EndpointRequestDraft,
  EndpointScanResponse,
  ScanResult,
  ScanResultItem,
  StackConfig,
  StackScanResponse,
} from "../../types/scan";

type ConfigProps = {
  common: CommonConfig;
  endpointRequests: EndpointRequestDraft[];
  stack: StackConfig;
};

export function ReportConfigPanel({ common, endpointRequests, stack }: ConfigProps) {
  return (
    <section className="rounded-[28px] border border-slate-200 bg-white/88 p-6">
      <div className="border-b border-slate-200 pb-5">
        <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Configured Targets</p>
        <h2 className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-slate-950">설정 내용</h2>
      </div>
      <div className="mt-5 space-y-4">
        <article className="rounded-3xl border border-slate-200 bg-slate-50/80 p-5">
          <p className="text-sm text-slate-600">Base URL</p>
          <p className="mt-2 font-semibold text-slate-950">{common.baseUrl}</p>
          <p className="mt-2 text-sm text-slate-500">
            로그인: {common.loginRequired ? common.authMode.toUpperCase() : "비로그인"}
          </p>
        </article>
        <article className="rounded-3xl border border-slate-200 bg-slate-50/80 p-5">
          <p className="text-sm text-slate-600">기술 스택</p>
          <p className="mt-2 font-semibold text-slate-950">{stack.stackName || "미입력"}</p>
        </article>
        {endpointRequests.filter((request) => request.path.trim()).map((request) => (
          <article key={request.id} className="rounded-3xl border border-slate-200 bg-slate-50/80 p-5">
            <div className="flex flex-wrap items-center gap-3">
              <span className={["rounded-full px-2.5 py-1 text-[11px] font-semibold ring-1", methodTone(request.method)].join(" ")}>
                {request.method}
              </span>
              <h3 className="font-semibold text-slate-950">{request.name}</h3>
            </div>
            <p className="mt-3 rounded-2xl border border-slate-200 bg-white px-4 py-3 font-mono text-sm text-slate-700">
              {composeRequestUrl(common.baseUrl, request.path)}
            </p>
          </article>
        ))}
      </div>
    </section>
  );
}

function resultTone(result: ScanResultItem) {
  const normalizedStatus = result.status.toLowerCase();
  const normalizedEvidence = result.evidence.toLowerCase();

  if (
    normalizedEvidence.includes("connection refused") ||
    normalizedEvidence.includes("failed to establish a new connection") ||
    normalizedEvidence.includes("max retries exceeded") ||
    normalizedEvidence.includes("connectionpool") ||
    normalizedStatus === "timeout"
  ) {
    return {
      badge: "대상 접속 실패",
      badgeClass: "bg-amber-100 text-amber-800 ring-amber-200",
      summary: "대상 서비스에 연결되지 않아 테스트를 끝까지 진행하지 못했습니다.",
    };
  }

  if (result.vulnerable) {
    return {
      badge: "취약 징후 발견",
      badgeClass: "bg-rose-100 text-rose-800 ring-rose-200",
      summary: "현재 응답 기준으로 추가 확인이 필요한 징후가 감지되었습니다.",
    };
  }

  if (normalizedStatus === "completed" || normalizedStatus === "success") {
    return {
      badge: "검사 완료",
      badgeClass: "bg-emerald-100 text-emerald-800 ring-emerald-200",
      summary: "현재 조건에서는 요청과 결과 수집이 정상적으로 끝났습니다.",
    };
  }

  if (normalizedStatus === "error") {
    return {
      badge: "추가 확인 필요",
      badgeClass: "bg-amber-100 text-amber-800 ring-amber-200",
      summary: "테스트가 완전히 끝나지 않아 확인이 더 필요합니다.",
    };
  }

  return {
    badge: "검사 완료",
    badgeClass: "bg-sky-100 text-sky-800 ring-sky-200",
    summary: "검사 응답이 수집되었습니다.",
  };
}

function ResultSection({
  title,
  scanId,
  status,
  count,
  results,
}: {
  title: string;
  scanId: string;
  status: string;
  count: number;
  results: ScanResultItem[];
}) {
  return (
    <section className="rounded-[28px] border border-slate-200 bg-white/88 p-6">
      <div className="border-b border-slate-200 pb-5">
        <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Backend Result</p>
        <h2 className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-slate-950">{title}</h2>
        <div className="mt-4 flex flex-wrap gap-3">
          <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs text-slate-700">
            Scan ID: {scanId}
          </span>
          <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs text-slate-700">
            상태: {status === "Completed" ? "검사 완료" : status}
          </span>
          <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs text-slate-700">
            Findings: {count}
          </span>
        </div>
      </div>
      <div className="mt-5 space-y-4">
        {results.length === 0 ? (
          <article className="rounded-3xl border border-slate-200 bg-slate-50/80 p-5 text-sm text-slate-600">
            실행 결과가 없습니다.
          </article>
        ) : null}
        {results.map((result) => {
          const tone = resultTone(result);

          return (
            <article key={`${title}-${result.poc_name}-${result.status}-${result.evidence}`} className="rounded-3xl border border-slate-200 bg-slate-50/80 p-5">
              <div className="flex flex-wrap items-center gap-3">
                <span className={["rounded-full px-2.5 py-1 text-[11px] font-semibold ring-1", tone.badgeClass].join(" ")}>
                  {tone.badge}
                </span>
                <h3 className="font-semibold text-slate-950">{result.poc_name}</h3>
              </div>
              <p className="mt-3 text-sm font-medium text-slate-800">{tone.summary}</p>
              <p className="mt-2 text-sm leading-6 text-slate-600">{result.description || "설명 없음"}</p>
              <div className="mt-4 rounded-2xl border border-slate-200 bg-white p-4">
                <p className="text-xs uppercase tracking-[0.24em] text-slate-500">세부 정보</p>
                <p className="mt-3 whitespace-pre-wrap break-words text-sm leading-6 text-slate-700">
                  {result.evidence || "추가 정보가 없습니다."}
                </p>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}

function StackResultSection({ data }: { data: StackScanResponse }) {
  return (
    <ResultSection
      title="스택 검사 결과"
      scanId={data.scan_id}
      status={data.status}
      count={data.results.length}
      results={data.results}
    />
  );
}

function EndpointResultSection({
  data,
  index,
}: {
  data: EndpointScanResponse;
  index: number;
}) {
  const endpoint = data.endpoints?.[0];
  const endpointLabel =
    endpoint && endpoint.path
      ? `${endpoint.method ?? "GET"} ${endpoint.path}`
      : `엔드포인트 ${index + 1}`;

  return (
    <ResultSection
      title={`엔드포인트 검사 결과 ${index + 1} - ${endpointLabel}`}
      scanId={data.scan_id}
      status={data.status}
      count={data.results.length}
      results={data.results}
    />
  );
}

type ResultProps = {
  scanResult: ScanResult;
};

export function ReportResultPanel({ scanResult }: ResultProps) {
  return (
    <div className="space-y-6">
      {scanResult.stack_scan ? <StackResultSection data={scanResult.stack_scan} /> : null}
      {scanResult.endpoint_scans?.map((scan, index) => (
        <EndpointResultSection key={scan.scan_id} data={scan} index={index} />
      ))}
    </div>
  );
}