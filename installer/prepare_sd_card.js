ObjC.import("stdlib");

const app = Application.currentApplication();
app.includeStandardAdditions = true;

function promptText(message, defaultAnswer) {
  const result = app.displayDialog(message, {
    defaultAnswer,
    buttons: ["Cancel", "Continue"],
    defaultButton: "Continue",
    cancelButton: "Cancel",
  });
  return result.textReturned;
}

function showError(message) {
  app.displayDialog(String(message), {
    buttons: ["OK"],
    defaultButton: "OK",
    withIcon: "stop",
  });
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function main() {
  const appPath = ObjC.unwrap($.NSBundle.mainBundle.bundlePath);
  const resourcesDir = `${appPath}/Contents/Resources`;
  const prepScript = `${resourcesDir}/prepare_sd_card.sh`;

  const displayId = promptText("Display number (1, 2, or 3):", "1").trim();
  if (!["1", "2", "3"].includes(displayId)) {
    showError("Display number must be 1, 2, or 3.");
    return;
  }

  const piHostname = promptText("Hostname for this Pi:", `podium-${displayId}`).trim();
  const piUsername = promptText("Pi username:", "event").trim();
  const defaultServerHost = displayId === "1" ? `${piHostname}.local` : "podium-1.local";
  const serverHost = promptText("Server hostname:", defaultServerHost).trim();

  const shellCommand = [
    prepScript,
    "--display", displayId,
    "--pi-username", piUsername,
    "--hostname", piHostname,
    "--server-host", serverHost,
    "--eject",
  ].map(shellQuote);

  try {
    const output = app.doShellScript(shellCommand.join(" "));
    app.displayDialog(output, {
      buttons: ["OK"],
      defaultButton: "OK",
      withTitle: "Podium SD Card Prepared",
    });
  } catch (error) {
    showError(error.message || error.toString());
  }
}

main();
