function renderTemplateString(template, context) {
  return String(template).replace(/\{\{([\s\S]+?)\}\}/g, (_, expression) => {
    try {
      return Function(
        "ctx",
        `with (ctx) { return (${expression.trim()}); }`
      )(context);
    } catch (error) {
      return `[template-error:${error.message}]`;
    }
  });
}

module.exports = { renderTemplateString };
