import { useState } from "react";

type ScanResult = {
  scan_id: string;
  status: string;
  base_url: string;
  stack_name: string;
  results: {
    poc_name: string;
    status: string;
    description: string;
    evidence: string;
    raw_output: string;
    debug_log?: string;
    vulnerable: boolean;
  }[];
};

type StackInfo = {
  stackName: string;
  scanResult?: ScanResult;
  //stackVersion: string;
};

type Props = {
  url: string;
  initialEndpoints: string[];
  initialStackInfo: StackInfo;
  onNext: (endpoints: string[], stackInfo: StackInfo) => void;
  onPrev: () => void;
};

const EMPTY_ENDPOINTS = ["", "", ""];

type NormalizedEndpointResult =
  | { isValid: true; normalized: string }
  | { isValid: false; message: string };

function normalizeEndpoint(
  baseUrl: string,
  rawEndpoint: string,
): NormalizedEndpointResult {
  const trimmedEndpoint = rawEndpoint.trim();

  if (!trimmedEndpoint) {
    return { isValid: true, normalized: "" };
  }

  if (trimmedEndpoint.startsWith("/")) {
    return { isValid: true, normalized: trimmedEndpoint };
  }

  try {
    const base = new URL(baseUrl);
    const endpointUrl = new URL(trimmedEndpoint);

    if (base.origin !== endpointUrl.origin) {
      return {
        isValid: false,
        message:
          "엔드포인트는 입력한 사이트와 같은 도메인만 사용할 수 있습니다.",
      };
    }

    return {
      isValid: true,
      normalized: `${endpointUrl.pathname}${endpointUrl.search}${endpointUrl.hash}`,
    };
  } catch {
    return {
      isValid: false,
      message: "엔드포인트는 /path 또는 같은 사이트의 전체 URL로 입력해주세요.",
    };
  }
}

function InputPage({
  url,
  initialEndpoints,
  initialStackInfo,
  onNext,
  onPrev,
}: Props) {
  const [endpointInputs, setEndpointInputs] = useState(() => {
    const nextInputs = [...EMPTY_ENDPOINTS];

    initialEndpoints
      .slice(0, EMPTY_ENDPOINTS.length)
      .forEach((endpoint, index) => {
        nextInputs[index] = endpoint;
      });

    return nextInputs;
  });
  const [stackName, setStackName] = useState(initialStackInfo.stackName);
  // const [stackVersion, setStackVersion] = useState(
  //   initialStackInfo.stackVersion,
  // );
  const [errorMessage, setErrorMessage] = useState("");

  const handleEndpointChange = (index: number, value: string) => {
    setEndpointInputs((prev) => {
      const next = [...prev];
      next[index] = value;
      return next;
    });

    if (errorMessage) {
      setErrorMessage("");
    }
  };

  const handleStackNameChange = (value: string) => {
    setStackName(value);

    if (errorMessage) {
      setErrorMessage("");
    }
  };

  // const handleStackVersionChange = (value: string) => {
  //   setStackVersion(value);

  //   if (errorMessage) {
  //     setErrorMessage("");
  //   }
  // };

  const handleNextClick = async () => {
    const normalizedEndpoints: string[] = [];

    for (const endpoint of endpointInputs) {
      const result = normalizeEndpoint(url, endpoint);

      if (!result.isValid) {
        setErrorMessage(result.message);
        return;
      }

      if (result.normalized) {
        normalizedEndpoints.push(result.normalized);
      }
    }

    if (normalizedEndpoints.length === 0) {
      setErrorMessage("최소 1개 이상의 엔드포인트를 입력해주세요.");
      return;
    }

    setErrorMessage("");
    try {
      const response = await fetch("/api/v1/stack/scans", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          base_url: url,
          stack_name: stackName.trim(),
          endpoints: normalizedEndpoints,
      }),
    });

    if (!response.ok) {
      throw new Error("스캔 요청에 실패했습니다.");
    }

    const data = await response.json();

    console.log("스캔 결과:", data);

    onNext(normalizedEndpoints, {
      stackName: stackName.trim(),
      scanResult: data,
    });
   } catch (error) {
      console.error(error);
      setErrorMessage("백엔드 요청 중 오류가 발생했습니다.");
   }
  };

  return (
    <div style={{ textAlign: "center", marginTop: "100px" }}>
      <h2>대상 정보 입력</h2>
      <p>대상 URL: {url}</p>
      <div className="inputEndpoint">
        <div>
          엔드포인트 {" : "}
          <input
            className="endpoints"
            placeholder="/admin"
            value={endpointInputs[0]}
            onChange={(e) => handleEndpointChange(0, e.target.value)}
          />
        </div>

        <div>
          엔드포인트 {" : "}
          <input
            className="endpoints"
            placeholder="/api/v1/users"
            value={endpointInputs[1]}
            onChange={(e) => handleEndpointChange(1, e.target.value)}
          />
        </div>

        <div>
          엔드포인트 {" : "}
          <input
            className="endpoints"
            placeholder="https://example.com/login"
            value={endpointInputs[2]}
            onChange={(e) => handleEndpointChange(2, e.target.value)}
          />
        </div>
      </div>
      <br />
      <div className="inputStack">
        <h2>사용 기술 / 프레임 워크 정보 입력</h2>
        <div>
          사용 기술 / 프레임 워크 이름{" : "}
          <input
            className="stacks"
            placeholder="React"
            value={stackName}
            onChange={(e) => handleStackNameChange(e.target.value)}
          />
        </div>
        <br />
        {/* <div>
          스택 버전{" : "}
          <input
            className="stacks"
            placeholder="19"
            value={stackVersion}
            onChange={(e) => handleStackVersionChange(e.target.value)}
          />
        </div> */}
      </div>
      {errorMessage && (
        <p style={{ color: "crimson", marginTop: "12px" }}>{errorMessage}</p>
      )}
      <div className="NavBtn">
        <button onClick={onPrev} style={{ marginRight: "10px" }}>
          이전
        </button>
        <button onClick={handleNextClick}>다음</button>
      </div>
    </div>
  );
}

export default InputPage;
