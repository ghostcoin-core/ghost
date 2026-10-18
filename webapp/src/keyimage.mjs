// The key as an image, drawn on a canvas in the page and handed to the
// browser's download. Nothing is uploaded; the canvas is cleared after.

const WIDTH = 960;
const HEIGHT = 460;

function draw(canvas, keyText) {
  const groups = keyText.trim().split(/\s+/);
  const rows = [];
  for (let i = 0; i < groups.length; i += 4) rows.push(groups.slice(i, i + 4).join("  "));
  canvas.width = WIDTH;
  canvas.height = 150 + rows.length * 70;
  const g = canvas.getContext("2d");
  g.fillStyle = "#ffffff";
  g.fillRect(0, 0, canvas.width, canvas.height);
  g.fillStyle = "#111111";
  g.font = "600 34px system-ui, sans-serif";
  g.fillText("Ghost Phantom Key", 40, 60);
  g.font = "52px ui-monospace, monospace";
  rows.forEach((row, i) => g.fillText(row, 40, 140 + i * 70));
  g.fillStyle = "#b45309";
  g.font = "22px system-ui, sans-serif";
  g.fillText("Whoever holds these digits holds the coin. Keep this image offline.", 40, canvas.height - 30);
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
