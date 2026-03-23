import { useState } from "react";
import MainPage from "./pages/MainPage";
import InputPage from "./pages/InputPage";

const STEPS = ["main", "scan", "result"];

function App() {
  const [stepIndex, setStepIndex] = useState(0);
  const [url, setUrl] = useState("");
  const [endpoints, setEndpoints] = useState<string[]>([]);

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

  const handleSubmitEndpoints = (nextEndpoints: string[]) => {
    setEndpoints(nextEndpoints);
    handleNext();
  };

  return (
    <>
      {currentStep === "main" && <MainPage onStart={handleStart} />}

      {currentStep === "scan" && (
        <InputPage
          url={url}
          initialEndpoints={endpoints}
          onNext={handleSubmitEndpoints}
          onPrev={handlePrev}
        />
      )}

      {currentStep === "result" && (
        <div style={{ textAlign: "center", marginTop: "100px" }}>
          <h2>진단 대상 확인</h2>
          <p>입력된 URL: {url}</p>
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
