import { useState } from "react";
import MainPage from "./pages/MainPage";
import InputPage from "./pages/InputPage";

const STEPS = ["main", "scan", "result"];

type StackInfo = {
  stackName: string;
  stackVersion: string;
};

function App() {
  const [stepIndex, setStepIndex] = useState(0);
  const [url, setUrl] = useState("");
  const [endpoints, setEndpoints] = useState<string[]>([]);
  const [stackInfo, setStackInfo] = useState<StackInfo>({
    stackName: "",
    stackVersion: "",
  });

  const currentStep = STEPS[stepIndex];

  const handleNext = () => {
    setStepIndex((prev) => Math.min(prev + 1, STEPS.length - 1));
  };

  const handlePrev = () => {
    setStepIndex((prev) => Math.max(prev - 1, 0));
  };

  const handleStart = (inputUrl: string) => {
    setUrl(inputUrl);
    handleNext();
  };

  const handleSubmitScanInfo = (
    nextEndpoints: string[],
    nextStackInfo: StackInfo,
  ) => {
    setEndpoints(nextEndpoints);
    setStackInfo(nextStackInfo);
    handleNext();
  };

  return (
    <>
      {currentStep === "main" && <MainPage onStart={handleStart} />}

      {currentStep === "scan" && (
        <InputPage
          url={url}
          initialEndpoints={endpoints}
          initialStackInfo={stackInfo}
          onNext={handleSubmitScanInfo}
          onPrev={handlePrev}
        />
      )}

      {currentStep === "result" && (
        <div style={{ textAlign: "center", marginTop: "100px" }}>
          <h2>진단 대상 확인</h2>
          <p>입력된 URL: {url}</p>
          <p style={{ marginTop: "12px" }}>
            사용 스택: {stackInfo.stackName || "미입력"}
          </p>
          <p>스택 버전: {stackInfo.stackVersion || "미입력"}</p>
          <p style={{ marginTop: "12px" }}>입력된 엔드포인트</p>
          <ul style={{ listStyle: "none", padding: 0 }}>
            {endpoints.map((endpoint) => (
              <li key={endpoint}>{endpoint}</li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

export default App;
