import { useState } from "react";
import MainPage from "./pages/MainPage";

function App() {
  const [step, setStep] = useState("main");
  const [url, setUrl] = useState("");

  const handleStart = (inputUrl: string) => {
    setUrl(inputUrl);
    setStep("scan");
  };

  return (
    <>
      {step === "main" && <MainPage onStart={handleStart} />}

      {step === "scan" && (
        <div style={{ textAlign: "center", marginTop: "100px" }}>
          <h2>진단 페이지</h2>
          <p>입력된 URL: {url}</p>
        </div>
      )}
    </>
  );
}

export default App;