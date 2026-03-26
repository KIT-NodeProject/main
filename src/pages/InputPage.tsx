import { useState } from "react";

type StackInfo = {
  stackName: string;
  stackVersion: string;
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
  const [stackVersion, setStackVersion] = useState(
    initialStackInfo.stackVersion,
  );
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

  const handleStackVersionChange = (value: string) => {
    setStackVersion(value);

    if (errorMessage) {
      setErrorMessage("");
    }
  };

  const handleNextClick = () => {
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
    onNext(normalizedEndpoints, {
      stackName: stackName.trim(),
      stackVersion: stackVersion.trim(),
    });
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
        <h2>스택 정보 입력</h2>
        <div>
          스택 이름{" : "}
          <input
            className="stacks"
            placeholder="React"
            value={stackName}
            onChange={(e) => handleStackNameChange(e.target.value)}
          />
        </div>
        <br />
        <div>
          스택 버전{" : "}
          <input
            className="stacks"
            placeholder="19"
            value={stackVersion}
            onChange={(e) => handleStackVersionChange(e.target.value)}
          />
        </div>
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
