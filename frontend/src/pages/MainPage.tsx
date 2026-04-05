import { useState } from "react";

type Props = {
  onStart: (url: string) => void;
};

function MainPage({ onStart }: Props) {
  const [url, setUrl] = useState("");

  const handleClick = () => {
    if (!url.startsWith("http")) {
      alert("URL 형식이 올바르지 않습니다");
      return;
    }
    onStart(url);
  };

  return (
    <div style={{ textAlign: "center", marginTop: "100px" }}>
      <h1>보안 진단 도구</h1>

      <input
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="https://example.com"
        style={{ padding: "10px", width: "300px" }}
      />

      <br />

      <button onClick={handleClick} style={{ marginTop: "20px" }}>
        진단 시작
      </button>
    </div>
  );
}

export default MainPage;
