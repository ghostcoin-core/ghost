// The key as an image, drawn on a canvas in the page and handed to the
// browser's download. Nothing is uploaded; the canvas is cleared after. It
// is a convenience beside writing the key down, never the only backup.

const WIDTH = 1120;
const HEIGHT = 460;

// The key's rows: its words numbered, four to a row, or its digit groups,
// four to a row.
function rows(keyText) {
  const parts = keyText.trim().split(/\s+/);
  const words = /[a-z]/i.test(keyText);
  const cells = words ? parts.map((w, i) => `${String(i + 1).padStart(2, "0")} ${w}`.padEnd(11)) : parts;
  const out = [];
  for (let i = 0; i < cells.length; i += 4) out.push(cells.slice(i, i + 4).join(words ? " " : "  ").trimEnd());
  return { out, words };
}

function draw(canvas, keyText) {
  const { out, words } = rows(keyText);
  canvas.width = WIDTH;
  canvas.height = 150 + out.length * 64;
  const g = canvas.getContext("2d");
  g.fillStyle = "#ffffff";
  g.fillRect(0, 0, canvas.width, canvas.height);
  g.fillStyle = "#111111";
  g.font = "600 34px system-ui, sans-serif";
  g.fillText("Ghost Phantom Key", 40, 60);
  g.font = words ? "36px ui-monospace, monospace" : "52px ui-monospace, monospace";
  out.forEach((row, i) => g.fillText(row, 40, 130 + i * 64));
  g.fillStyle = "#b45309";
  g.font = "22px system-ui, sans-serif";
  g.fillText(
    `Whoever holds these ${words ? "words" : "digits"} holds the coin. Write them down too; keep this image offline.`,
    40,
    canvas.height - 30,
  );
}

export async function downloadKeyImage(keyText, fileName = "phantom-key.png") {
  const canvas = document.createElement("canvas");
  canvas.width = WIDTH;
  canvas.height = HEIGHT;
  draw(canvas, keyText);
  const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
  canvas.getContext("2d").clearRect(0, 0, canvas.width, canvas.height);
  canvas.width = 0;
  if (!blob) throw new Error("the browser could not draw the image");
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
