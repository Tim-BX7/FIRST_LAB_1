document.querySelectorAll("textarea[readonly]").forEach((node) => {
  node.addEventListener("focus", () => node.select());
});
