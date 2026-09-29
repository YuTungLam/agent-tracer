// Fixed architecture of this lab; highlights describe an observation boundary,
// not a replay of every internal action or a causal provenance graph.
const FLOW_EVENT_MAP = Object.freeze({
  RUN_STARTED: {nodes:["runner"],edges:[],text:"The experiment has entered the runner; this does not yet indicate model or tool execution."},
  RUN_END: {nodes:["runner"],edges:[],text:"The runner records the final run status. RUN_END alone is not evidence of a passing utility evaluation."},
  EPISODE_STARTED: {nodes:["pipeline"],edges:[],text:"A complete query begins; the system prompt and user query are initialized afterward."},
  EPISODE_ENDED: {nodes:["exit"],edges:[],text:"The pipeline returned or raised an error. The suite may retry; this event does not imply task success."},
  MODEL_REQUEST: {nodes:["request"],edges:["request_api"],text:"The actual request body is recorded at the outbound HTTP boundary; this does not establish server receipt."},
  MODEL_RESPONSE: {nodes:["api"],edges:["api_parse"],text:"The client received an HTTP response. It may contain an error and has not yet been parsed into a native message."},
  MODEL_PARSED: {nodes:["parse"],edges:[],text:"The response was converted into a native assistant message. Having no tool calls does not automatically imply task success."},
  MODEL_ERROR: {nodes:["request","api","parse"],edges:[],text:"The error occurred within the model call or adapter boundary and may involve transport, the SDK, or parsing. The full range is highlighted when the log does not localize it further."},
  TOOL_CALL_PROPOSED: {nodes:["parse"],edges:[],text:"The model's original tool-call proposal is recorded before executor processing; the tool has not necessarily executed."},
  TOOL_RUNTIME_STARTED: {nodes:["runtime"],edges:[],text:"Execution entered the top-level FunctionsRuntime, before internal argument validation, default filling, and dependency injection."},
  TOOL_RUNTIME_RETURNED: {nodes:["runtime"],edges:[],text:"The top-level runtime returned a raw result or error; the tool message has not necessarily been added to the history yet."},
  ENVIRONMENT_CHANGE: {nodes:["environment"],edges:[],text:"An environment-state change was observed across the tool call. This environment snapshot is not model input."},
  TOOL_OUTPUT_INTERVENTION: {nodes:["result"],edges:[],text:"In the separate Canary condition, a UUID suffix is planned after native execution and before tool history publication. Follow the linked result and request to verify application and exposure."},
  TOOL_RESULT: {nodes:["result"],edges:["result_history"],text:"After completing the batch, the executor creates tool messages and adds them to history. An unknown tool can produce an error message without entering the runtime."},
  TOOL_OUTPUT_EXPOSED: {nodes:["history","request"],edges:["history_request"],text:"A tool message was included in this round's outbound request; this does not establish model attention or use."}
});

function eventHasError(event) {
  const data = event?.data && typeof event.data === "object" ? event.data : {};
  return event?.event_type === "MODEL_ERROR" || !!data.error || !!data.message?.error ||
    !!data.raised_exception_type || !!data.error_type ||
    (typeof data.status_code === "number" && data.status_code >= 400) ||
    ["error","failed","completed_with_issues"].includes(data.status);
}

function flowLocation(event) {
  if (!event) return {nodes:[],edges:[],tone:"none",text:"Select a timeline event to see its location in the diagram."};
  const key = typeof event.event_type === "string" ? event.event_type : "";
  const match = Object.prototype.hasOwnProperty.call(FLOW_EVENT_MAP,key) ? FLOW_EVENT_MAP[key] : null;
  return {
    nodes:match ? [...match.nodes] : [],
    edges:match ? [...match.edges] : [],
    tone:eventHasError(event) ? "error" : match ? "active" : "unknown",
    text:match ? match.text : "This event is not yet mapped to a known component. The original event remains available in the details."
  };
}

function updateFlow(event) {
  const state = flowLocation(event);
  let focusNode = null;
  for (const node of document.querySelectorAll("[data-flow-node]")) {
    const active = state.nodes.includes(node.getAttribute("data-flow-node"));
    node.classList.toggle("is-active",active);
    node.classList.toggle("is-error",active && state.tone === "error");
    if (active) {
      node.setAttribute("aria-current","step");
      focusNode ??= node;
    }
    else node.removeAttribute("aria-current");
  }
  for (const edge of document.querySelectorAll("[data-flow-edge]")) {
    const active = state.edges.includes(edge.getAttribute("data-flow-edge"));
    edge.classList.toggle("is-active",active);
    edge.classList.toggle("is-error",active && state.tone === "error");
  }
  const status = document.getElementById("flow-selection");
  status.textContent = event ? "Selected event #" + String(event.event_sequence ?? "—") + " · " + String(event.event_type ?? "Unknown type") : "No event selected";
  status.dataset.tone = state.tone;
  document.getElementById("flow-explanation").textContent = state.text;
  // Keep the highlighted component in the diagram's horizontal viewport without
  // scrolling the page away from the user's selected timeline row.
  const viewport = document.getElementById("flow-scroll");
  if (focusNode?.getBoundingClientRect && viewport?.getBoundingClientRect) {
    const target = focusNode.getBoundingClientRect(), bounds = viewport.getBoundingClientRect();
    if (target.right > bounds.right - 12) viewport.scrollLeft += target.right - bounds.right + 12;
    else if (target.left < bounds.left + 12) viewport.scrollLeft += target.left - bounds.left - 12;
  }
}

function initializeFlow(mode) {
  if (mode === false) {
    document.getElementById("flow-api-label").textContent = "Scripted response";
    document.getElementById("flow-api-sub").textContent = "MockTransport · offline";
  } else if (mode !== true) {
    document.getElementById("flow-api-label").textContent = "Model interface (unknown type)";
  }
  updateFlow(null);
}
