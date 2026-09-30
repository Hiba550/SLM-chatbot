/* Meridian workspace behavior */
const $ = (id) => document.getElementById(id);
const PRODUCT_NAME = "Meridian";
const THEME_KEY = "meridian_theme";
const BOT_MARK = '<svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><path d="M6 25V7l10 11L26 7v18" stroke="currentColor" stroke-width="2.7" stroke-linecap="round" stroke-linejoin="round"/><circle cx="16" cy="18" r="2.2" fill="currentColor"/></svg>';

let authToken = null;
let currentUser = {};
let currentSessionId = null;
let activeMessages = [];
let currentView = "chat";
let isSending = false;
let auditRecords = [];
let healthInterval = null;
let toastTimer = null;
let controlsBound = false;

let sessionId = null;
let csrfToken = null;
let access = {};
let sessionEpoch = 0;
let pendingController = null;
let sessionCheck = null;
let expiryTimer = null;
let loginRetryTimer = null;
let directoryRecords = [];
let useChatContext = true;
let adminUsersPayload = { users: [], roles: [], departments: [] };
let adminRolesPayload = { roles: [], catalog: [] };
let adminOverview = null;
let databaseCatalog = { sources: [], relationships: [], summary: {} };
let selectedRoleId = null;
let userScopePayload = null;
let adminDirectoryTab = "users";
const dismissedWorkspaceTabs = new Set();

function applyTheme(theme) {
  const dark = theme === "dark";
  document.body.dataset.theme = dark ? "dark" : "light";
  const button = $("themeToggle");
  if (button) {
    const label = dark ? "Switch to light mode" : "Switch to dark mode";
    button.setAttribute("aria-label", label);
    button.title = label;
    button.setAttribute("aria-pressed", String(dark));
  }
}

function initializeTheme() {
  let theme = "light";
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "dark" || saved === "light") theme = saved;
    else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) theme = "dark";
  } catch { /* Theme remains available when browser storage is disabled. */ }
  applyTheme(theme);
}

function toggleTheme() {
  const next = document.body.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(next);
  try { localStorage.setItem(THEME_KEY, next); } catch { /* Keep this page's choice for the current session. */ }
}

function roleInfo() {
  return { label: access.label || "Workspace", kicker: access.kicker || "Analytics", scope: access.description || "assigned data" };
}

function questions() { return access.questions || []; }

function acceptSession(data) {
  currentUser = data;
  sessionId = data.sessionId;
  authToken = sessionId;
  csrfToken = data.csrfToken;
  access = data.access || {};
  if (expiryTimer) clearTimeout(expiryTimer);
  expiryTimer = setTimeout(() => endSession("Your session has expired. Sign in again."),
    Math.max(0, new Date(data.expiresAt).getTime() - Date.now()));
}

async function apiFetch(url, options = {}) {
  const epoch = sessionEpoch;
  const headers = { ...options.headers };
  if (sessionId) headers["X-Session-ID"] = sessionId;
  if (options.method && options.method !== "GET") headers["X-CSRF-Token"] = csrfToken || "";
  const response = await fetch(url, { ...options, headers, credentials: "same-origin", cache: "no-store" });
  if (epoch !== sessionEpoch) throw new DOMException("Session changed", "AbortError");
  if (response.status === 401) {
    const data = await response.clone().json();
    endSession(data.error || "Your session has expired. Sign in again.");
    throw new DOMException("Session ended", "AbortError");
  }
  return response;
}

function purgeHistory() {
  try {
    for (const key of Object.keys(sessionStorage)) {
      if (key.startsWith("insightbot_") || key === "token" || key === "user") sessionStorage.removeItem(key);
    }
  } catch { /* Storage may be disabled by browser policy. */ }
}

function historyKey() {
  return "insightbot_history_" + sessionId + "_" + (access.fingerprint || "");
}

function loadAllSessions() {
  try {
    const value = JSON.parse(sessionStorage.getItem(historyKey()) || "[]");
    return Array.isArray(value) ? value.filter((session) =>
      session && typeof session.id === "string" && Array.isArray(session.messages)
    ).map((session) => session.title === "New analysis" && !session.messages.length
      ? { ...session, title: "New chat" } : session)
      .sort((a, b) => new Date(b.updatedAt || b.createdAt).getTime() - new Date(a.updatedAt || a.createdAt).getTime()) : [];
  } catch {
    return [];
  }
}

function saveAllSessions(sessions) {
  try {
    sessionStorage.setItem(historyKey(), JSON.stringify(sessions));
    return true;
  } catch {
    showToast("Conversation history could not be saved in this browser.");
    return false;
  }
}

function getSession(id) {
  return loadAllSessions().find((session) => session.id === id) || null;
}

function createSession() {
  const id = "s_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
  dismissedWorkspaceTabs.delete(id);
  const session = {
    id: id,
    title: "New chat",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    messages: [],
    useContext: true,
  };
  saveAllSessions([session].concat(loadAllSessions()).slice(0, 30));
  return session;
}

function updateSessionMessages(id, messages, title) {
  const sessions = loadAllSessions();
  const index = sessions.findIndex((session) => session.id === id);
  if (index < 0) return;
  sessions[index].messages = messages;
  sessions[index].updatedAt = new Date().toISOString();
  if (title) sessions[index].title = title;
  saveAllSessions(sessions);
}

function updateSessionContext(id, enabled) {
  const sessions = loadAllSessions();
  const session = sessions.find((item) => item.id === id);
  if (!session) return;
  session.useContext = Boolean(enabled);
  saveAllSessions(sessions);
}

async function deleteSession(id) {
  if (isSending) return;
  try {
    const response = await apiFetch("/conversations/" + encodeURIComponent(id), { method: "DELETE" });
    if (!response.ok) throw new Error("Conversation could not be deleted.");
  } catch (error) {
    if (error.name !== "AbortError") showToast("Could not remove the conversation. Try again.");
    return;
  }
  saveAllSessions(loadAllSessions().filter((session) => session.id !== id));
  if (currentSessionId === id) {
    const next = loadAllSessions()[0];
    if (next) loadSession(next.id);
    else startNewChat(true);
  } else {
    renderSessionsList();
  }
}

function newMessageId() {
  return "m_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function pushMessage(message) {
  message.id = message.id || newMessageId();
  activeMessages.push(message);
  const firstQuestion = activeMessages.find((item) => item.role === "user");
  const title = firstQuestion
    ? (firstQuestion.text.length > 48 ? firstQuestion.text.slice(0, 48) + "..." : firstQuestion.text)
    : "New chat";
  updateSessionMessages(currentSessionId, activeMessages, title);
  $("chatSessionTitle").textContent = title;
  renderSessionsList();
}

function showScreen(name) {
  document.querySelectorAll(".screen").forEach((screen) => screen.classList.remove("active"));
  const target = $(name + "Screen");
  if (target) target.classList.add("active");
  const skipLink = $("skipLink");
  if (skipLink) {
    skipLink.href = name === "chat" ? "#chatMessages" : "#signinTitle";
    skipLink.textContent = name === "chat" ? "Skip to workspace" : "Skip to sign in";
  }
}

function formatTime(iso) {
  const date = iso ? new Date(iso) : new Date();
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function formatRelativeDate(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  const minutes = Math.floor((Date.now() - date.getTime()) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return minutes + "m ago";
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours + "h ago";
  const days = Math.floor(hours / 24);
  if (days === 1) return "yesterday";
  if (days < 7) return days + "d ago";
  return date.toLocaleDateString();
}

function togglePassword() {
  const input = $("passwordInput");
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  $("pwToggle").setAttribute("aria-pressed", String(show));
  $("pwToggle").setAttribute("aria-label", show ? "Hide password" : "Show password");
}

function showLoginError(message) {
  const element = $("loginError");
  element.textContent = message;
  element.classList.remove("hidden");
  requestAnimationFrame(() => element.focus({ preventScroll: true }));
}

function startLoginCooldown(seconds) {
  if (loginRetryTimer) clearInterval(loginRetryTimer);
  let remaining = Math.max(1, Number(seconds) || 1);
  const update = () => {
    $("loginBtn").disabled = true;
    $("loginBtnText").textContent = "Try again in " + remaining + "s";
    remaining -= 1;
    if (remaining < 0) {
      clearInterval(loginRetryTimer);
      loginRetryTimer = null;
      $("loginBtn").disabled = false;
      $("loginBtnText").textContent = "Enter workspace";
    }
  };
  update();
  loginRetryTimer = setInterval(update, 1000);
}

async function login(event) {
  event.preventDefault();
  const username = $("usernameInput").value.trim();
  const password = $("passwordInput").value;
  if (!username || !password) {
    showLoginError("Enter both your username and password.");
    (username ? $("passwordInput") : $("usernameInput")).focus();
    return;
  }

  $("loginBtnText").textContent = "Signing in";
  $("loginSpinner").classList.remove("hidden");
  $("loginBtn").disabled = true;
  $("loginError").classList.add("hidden");

  let retryAfter = 0;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: username, password: password }),
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal,
    });
    const data = await readJsonResponse(response);
    if (!response.ok) {
      showLoginError(data.error || "Sign-in failed. Check your details and try again.");
      retryAfter = response.status === 429 ? Number(response.headers.get("Retry-After")) || 60 : 0;
      return;
    }
    purgeHistory();
    sessionEpoch++;
    acceptSession(data);
    $("passwordInput").value = "";
    await initChatScreen();
    showScreen("chat");
  } catch (error) {
    showLoginError(error.name === "AbortError"
      ? "Sign-in took too long. Check the server and try again."
      : "Could not reach the workspace. Check the server connection and try again.");
  } finally {
    clearTimeout(timeout);
    $("loginBtnText").textContent = "Enter workspace";
    $("loginSpinner").classList.add("hidden");
    if (retryAfter) startLoginCooldown(retryAfter);
    else $("loginBtn").disabled = false;
  }
}

async function initializeFromSession() {
  $("bootScreen").classList.remove("hidden");
  try {
    const response = await fetch("/session", { credentials: "same-origin", cache: "no-store" });
    if (!response.ok) {
      purgeHistory();
      showScreen("login");
      if (response.status !== 401) showLoginError("Workspace access could not be verified. Try signing in again.");
      return;
    }
    const data = await response.json();
    // Keep only the history bound to this verified login and policy.
    acceptSession(data);
    for (const key of Object.keys(sessionStorage)) {
      if (key.startsWith("insightbot_history_") && key !== historyKey()) sessionStorage.removeItem(key);
    }
    sessionStorage.removeItem("token");
    sessionStorage.removeItem("user");
    await initChatScreen();
    showScreen("chat");
  } catch {
    endSession("Could not verify your session. Check the server connection and sign in again.");
  } finally {
    $("bootScreen").classList.add("hidden");
  }
}

async function refreshSession() {
  if (!authToken) return false;
  if (sessionCheck) return sessionCheck;
  sessionCheck = (async () => {
    try {
      const response = await apiFetch("/session");
      if (!response.ok) {
        endSession("Account access could not be verified. Sign in again when the service is available.");
        return false;
      }
      const data = await response.json();
      if (data.sessionId !== sessionId || data.access.fingerprint !== access.fingerprint) {
        endSession("Your workspace access has changed. Sign in again.");
        return false;
      }
      return true;
    } catch (error) {
      if (error.name !== "AbortError") endSession("Connection lost while verifying access. Sign in again to continue.");
      return false;
    } finally { sessionCheck = null; }
  })();
  return sessionCheck;
}

async function initChatScreen() {
  const role = currentUser.role;
  const roleDetails = roleInfo();
  const name = currentUser.fullName || currentUser.username || "User";
  const initial = name.trim().split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();

  $("userAvatarSidebar").textContent = initial || "U";
  $("userNameSidebar").textContent = name;
  $("userRoleBadge").textContent = roleDetails.label.toUpperCase();
  $("scopeLabel").textContent = role === "sales"
    ? "Sales · " + (currentUser.region || "unassigned")
    : roleDetails.label + " workspace";
  $("composerScopeLabel").textContent = access.label + " access";
  $("auditNavButton").classList.toggle("hidden", !access.canAudit);
  $("directoryNavButton").classList.toggle("hidden", !access.canReviewAccess);
  $("adminDashboardNavButton").classList.toggle("hidden", !access.canManageUsers);
  $("databaseMapNavButton").classList.toggle("hidden", !access.canViewSchema);
  $("accessSummary").textContent = access.description;
  $("chatInput").placeholder = "Ask about " + roleDetails.kicker.toLowerCase().replace(" analytics", "") + " data…";
  $("sessionExpiry").textContent = "Session ends " + formatTime(currentUser.expiresAt);

  renderQuickQuestions(role);
  renderSessionsList();
  const sessions = loadAllSessions();
  if (sessions.length) loadSession(sessions[0].id);
  else startNewChat(true);

  await checkHealth();
  if (healthInterval) clearInterval(healthInterval);
  healthInterval = setInterval(async () => { if (!document.hidden && await refreshSession()) checkHealth(); }, 60000);
}

function renderQuickQuestions(role) {
  const list = $("quickQuestions");
  list.innerHTML = "";
  questions().forEach((question) => {
    const button = document.createElement("button");
    button.className = "quick-btn";
    button.type = "button";
    button.textContent = question;
    button.addEventListener("click", () => submitQuestion(question));
    list.appendChild(button);
  });
}

function renderSuggestionRail(visible) {
  const rail = $("suggestionRail");
  rail.replaceChildren();
  rail.classList.toggle("hidden", !visible);
  if (!visible) return;
  questions().slice(0, 4).forEach((question) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = question;
    button.addEventListener("click", () => submitQuestion(question));
    rail.appendChild(button);
  });
}

function renderWorkspaceTabs() {
  const tabs = $("workspaceTabs");
  if (!tabs) return;
  tabs.replaceChildren();
  const sessions = loadAllSessions();
  let visible = sessions.filter((session) => !dismissedWorkspaceTabs.has(session.id)).slice(0, 3);
  const current = sessions.find((session) => session.id === currentSessionId);
  if (current && !visible.some((session) => session.id === current.id)) {
    visible = [current].concat(visible.slice(0, 2));
  }
  visible.forEach((session) => {
    const shell = document.createElement("div");
    shell.className = "workspace-tab-shell";
    const selected = session.id === currentSessionId;
    const button = document.createElement("button");
    button.className = "workspace-tab" + (selected ? " active" : "");
    button.type = "button";
    button.setAttribute("role", "tab");
    button.setAttribute("aria-selected", String(selected));
    button.title = session.title || "New chat";
    button.innerHTML = '<span class="workspace-tab-mark" aria-hidden="true">' + BOT_MARK + '</span>' +
      '<span class="workspace-tab-title">' + escHtml(session.title === "New chat" ? PRODUCT_NAME : (session.title || PRODUCT_NAME)) + '</span>';
    button.addEventListener("click", () => loadSession(session.id));
    shell.appendChild(button);
    if (selected) {
      const close = document.createElement("button");
      close.type = "button";
      close.className = "workspace-tab-close";
      close.setAttribute("aria-label", "Close conversation tab");
      close.title = "Close tab";
      close.textContent = "×";
      close.addEventListener("click", (event) => {
        event.stopPropagation();
        closeWorkspaceTab(session.id);
      });
      shell.appendChild(close);
    }
    tabs.appendChild(shell);
  });
}

function closeWorkspaceTab(id) {
  dismissedWorkspaceTabs.add(id);
  if (currentSessionId !== id) {
    renderWorkspaceTabs();
    return;
  }
  const next = loadAllSessions().find((session) => session.id !== id && !dismissedWorkspaceTabs.has(session.id));
  if (next) loadSession(next.id);
  else startNewChat(true);
}

function updateContextToggle() {
  const toggle = $("contextToggle");
  toggle.classList.toggle("active", useChatContext);
  toggle.setAttribute("aria-pressed", String(useChatContext));
  toggle.querySelector(".context-check").textContent = useChatContext ? "✓" : "";
}

function renderSessionsList() {
  renderWorkspaceTabs();
  const list = $("chatSessionsList");
  const search = $("sessionSearch").value.trim().toLowerCase();
  const sessions = loadAllSessions().filter((session) =>
    !search || String(session.title || "").toLowerCase().includes(search)
  );
  list.innerHTML = "";
  if (!sessions.length) {
    const empty = document.createElement("p");
    empty.className = "empty-list";
    empty.textContent = search ? "No matching conversations." : "Your conversations will appear here.";
    list.appendChild(empty);
    return;
  }

  const today = new Date().toDateString();
  let lastGroup = "";
  sessions.forEach((session) => {
    const updated = new Date(session.updatedAt);
    const age = Number.isNaN(updated.getTime()) ? 999 : Math.floor((new Date(today).getTime() - new Date(updated.toDateString()).getTime()) / 86400000);
    const group = age <= 0 ? "Today" : age === 1 ? "Yesterday" : age <= 7 ? "Last 7 days" : "Earlier";
    if (group !== lastGroup) {
      const heading = document.createElement("div");
      heading.className = "history-group-label";
      heading.textContent = group;
      list.appendChild(heading);
      lastGroup = group;
    }
    const item = document.createElement("div");
    item.className = "session-item" + (session.id === currentSessionId ? " active" : "");
    item.dataset.sessionId = session.id;
    item.setAttribute("role", "button");
    item.setAttribute("tabindex", "0");
    item.setAttribute("aria-current", session.id === currentSessionId ? "true" : "false");

    const title = document.createElement("div");
    title.className = "session-info";
    title.innerHTML = '<div class="session-title">' + escHtml(session.title || "New chat") + '</div>' +
      '<div class="session-time">' + escHtml(formatTime(session.updatedAt)) + '</div>';

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "session-delete";
    remove.dataset.deleteSession = session.id;
    remove.setAttribute("aria-label", "Delete conversation: " + (session.title || "New chat"));
    remove.title = "Delete conversation";
    remove.innerHTML = '<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M2 4h12M5 4V2h6v2M6 7v5m4-5v5M3 4l1 9h8l1-9" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" stroke-linejoin="round"/></svg>';

    item.append(title, remove);
    item.addEventListener("click", (event) => {
      if (!event.target.closest("[data-delete-session]")) loadSession(session.id);
    });
    item.addEventListener("keydown", (event) => {
      if ((event.key === "Enter" || event.key === " ") && !event.target.closest("[data-delete-session]")) {
        event.preventDefault();
        loadSession(session.id);
      }
    });
    list.appendChild(item);
  });
}

function loadSession(id) {
  if (isSending) return;
  const session = getSession(id);
  if (!session) return;
  dismissedWorkspaceTabs.delete(id);
  currentSessionId = id;
  activeMessages = (session.messages || []).map((message) => Object.assign({}, message));
  useChatContext = session.useContext !== false;
  updateContextToggle();
  showChatWorkspace(false);
  renderSessionsList();
  closeSidebar();
}

function startNewChat(silent) {
  if (isSending || !authToken) return;
  const session = createSession();
  currentSessionId = session.id;
  activeMessages = [];
  useChatContext = true;
  updateContextToggle();
  showChatWorkspace(true);
  renderSessionsList();
  if (!silent) $("chatInput").focus();
  closeSidebar();
}

async function clearCurrentChat() {
  if (isSending || !currentSessionId) return;
  const targetId = currentSessionId;
  try {
    const response = await apiFetch("/conversations/" + encodeURIComponent(targetId), { method: "DELETE" });
    if (!response.ok) throw new Error("Conversation could not be cleared.");
  } catch (error) {
    if (error.name !== "AbortError") showToast("Could not clear the conversation. Try again.");
    return;
  }
  if (currentSessionId !== targetId) {
    updateSessionMessages(targetId, [], "New chat");
    renderSessionsList();
    return;
  }
  activeMessages = [];
  updateSessionMessages(currentSessionId, [], "New chat");
  $("chatSessionTitle").textContent = "New chat";
  renderWelcome();
  renderSessionsList();
  $("chatInput").focus();
}

function roleIcon(role, index) {
  const icons = [
    '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M3 16V4m0 12h14M6 13l3-4 3 2 4-6" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M4 5h12v11H4zM7 8h6m-6 3h6m-6 3h3" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M3 6h14M5 3v6m10-6v6M4 10h12v7H4zM7 13h2m2 0h2" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><circle cx="7" cy="7" r="3" stroke="currentColor" stroke-width="1.35"/><path d="M2.8 16a4.2 4.2 0 0 1 8.4 0m1-6.7a3 3 0 1 0 0-4.6m1.5 6.4a3.8 3.8 0 0 1 3.5 3.8" stroke="currentColor" stroke-width="1.35" stroke-linecap="round"/></svg>',
  ];
  return icons[(index + (role === "inventory" ? 1 : 0)) % icons.length];
}

function renderWelcome() {
  const name = String(currentUser.fullName || currentUser.username || "").trim();
  const firstName = /^(?:system administrator|administrator|user)$/i.test(name) ? "" : name.split(/\s+/)[0];
  const hour = new Date().getHours();
  const greeting = hour < 12 ? "Good morning" : hour < 17 ? "Good afternoon" : "Good evening";
  $("chatMessages").innerHTML =
    '<section class="welcome-view" aria-labelledby="welcomeTitle">' +
      '<div class="welcome-brand-mark" aria-hidden="true">' + BOT_MARK + '</div>' +
      '<p class="welcome-greeting">' + escHtml(firstName ? greeting + ", " + firstName : greeting) + '</p>' +
      '<h2 id="welcomeTitle">Ask about your data. <span>See the source.</span></h2>' +
    '</section>';
  $("chatWorkspace").classList.add("welcome-mode");
  $("clearChatBtn").classList.add("hidden");
  renderSuggestionRail(false);
}

function showChatWorkspace(showWelcome) {
  currentView = "chat";
  $("assistantNavButton").classList.add("active");
  document.querySelectorAll(".workspace-nav .nav-link").forEach((el) => el.classList.toggle("active", el.id === "assistantNavButton"));
  $("chatInputArea").classList.remove("hidden");
  $("clearChatBtn").classList.toggle("hidden", showWelcome || !activeMessages.length);
  $("chatSubtitle").textContent = roleInfo().kicker;
  const session = getSession(currentSessionId);
  $("chatSessionTitle").textContent = session ? session.title : "New chat";

  if (showWelcome || !activeMessages.length) {
    renderWelcome();
    return;
  }
  $("chatWorkspace").classList.remove("welcome-mode");
  renderSuggestionRail(false);
  $("chatMessages").innerHTML = '<div class="message-list"></div>';
  const list = $("chatMessages").firstElementChild;
  activeMessages.forEach((message) => {
    if (message.role === "user") renderUserMessage(message.text, message.time, false, list);
    else renderBotMessage(message, false, list);
  });
  requestAnimationFrame(scrollToBottom);
}

async function checkHealth() {
  const refreshButton = $("refreshHealthBtn");
  refreshButton.classList.add("loading");
  try {
    const response = await apiFetch("/health");
    if (!response.ok) throw new Error("Service status unavailable");
    const data = await response.json();
    const dbOk = data.database === "ok";
    const modelOk = data.ollama === "ok";
    const state = dbOk && modelOk ? "online" : (dbOk || modelOk ? "partial" : "offline");
    $("statusIndicator").className = "connection-led " + state;
    $("headerConnectionLed").className = "connection-led " + state;
    $("statusText").textContent = dbOk && modelOk ? "Data services ready" :
      (!dbOk && !modelOk ? "Services unavailable" : (!dbOk ? "Database unavailable" : "Query engine unavailable"));
    $("modelLabel").textContent = modelOk ? "Query engine ready" : "Query engine offline";
    $("headerConnectionText").textContent = dbOk && modelOk ? "Services connected" :
      (!dbOk && !modelOk ? "Services unavailable" : (!dbOk ? "Database offline" : "Model offline"));
    $("headerConnectionState").title = "Database: " + data.database + " | Query engine: " + data.ollama;
  } catch {
    $("statusIndicator").className = "connection-led offline";
    $("headerConnectionLed").className = "connection-led offline";
    $("statusText").textContent = "Services unavailable";
    $("modelLabel").textContent = "Connection check failed";
    $("headerConnectionText").textContent = "Server unavailable";
  } finally {
    refreshButton.classList.remove("loading");
  }
}

function bindControls() {
  if (controlsBound) return;
  controlsBound = true;
  $("loginForm").addEventListener("submit", login);
  $("pwToggle").addEventListener("click", togglePassword);
  $("loginForm").addEventListener("input", () => $("loginError").classList.add("hidden"));
  ["keydown", "keyup"].forEach((name) => $("passwordInput").addEventListener(name, (event) => {
    $("capsLockHint").classList.toggle("hidden", !event.getModifierState("CapsLock"));
  }));
  $("newChatBtn").addEventListener("click", () => startNewChat(false));
  $("clearChatBtn").addEventListener("click", clearCurrentChat);
  $("composerScope").addEventListener("click", renderAccess);
  $("viewSourcesBtn").addEventListener("click", renderAccess);
  $("contextToggle").addEventListener("click", () => {
    useChatContext = !useChatContext;
    updateContextToggle();
    if (currentSessionId) updateSessionContext(currentSessionId, useChatContext);
  });
  $("logoutBtn").addEventListener("click", logout);
  $("themeToggle").addEventListener("click", toggleTheme);
  $("refreshHealthBtn").addEventListener("click", checkHealth);
  $("assistantNavButton").addEventListener("click", () => showChatWorkspace(false));
  $("exploreNavButton").addEventListener("click", renderExplore);
  $("historyNavButton").addEventListener("click", focusHistory);
  $("auditNavButton").addEventListener("click", loadAudit);
  $("adminDashboardNavButton").addEventListener("click", loadAdminDashboard);
  $("databaseMapNavButton").addEventListener("click", loadDatabaseMap);
  $("accessNavButton").addEventListener("click", renderAccess);
  $("scopeButton").addEventListener("click", renderAccess);
  $("directoryNavButton").addEventListener("click", loadDirectory);
  $("chatSessionsList").addEventListener("click", handleWorkspaceClick);
  document.addEventListener("visibilitychange", async () => {
    if (!authToken) return;
    $("chatScreen").classList.add("access-pending");
    if (!document.hidden && await refreshSession()) $("chatScreen").classList.remove("access-pending");
  });
  $("sessionSearch").addEventListener("input", renderSessionsList);
  $("chatForm").addEventListener("submit", (event) => {
    event.preventDefault();
    sendMessage();
  });
  $("chatInput").addEventListener("input", resizeComposer);
  $("chatInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      sendMessage();
    }
  });
  $("mobileSidebarOpen").addEventListener("click", openSidebar);
  $("mobileSidebarClose").addEventListener("click", closeSidebar);
  $("sidebarScrim").addEventListener("click", closeSidebar);
  $("chatMessages").addEventListener("click", handleWorkspaceClick);
  $("chatMessages").addEventListener("click", handleExploreClick);
  $("chatMessages").addEventListener("input", handleWorkspaceInput);
  $("modalRoot").addEventListener("click", handleAdminModalClick);
  $("modalRoot").addEventListener("submit", handleAdminModalSubmit);
  $("modalRoot").addEventListener("change", handleAdminModalChange);
  $("modalRoot").addEventListener("input", handleAdminModalChange);
  document.addEventListener("keydown", (event) => {
    const target = event.target;
    const typing = target && /INPUT|TEXTAREA|SELECT/.test(target.tagName);
    if (event.key === "Tab" && $("chatScreen").classList.contains("sidebar-open")) {
      const focusable = [...$("sidebar").querySelectorAll('button:not(:disabled),a,input,[tabindex="0"]')].filter((el) => el.getClientRects().length);
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
    if (authToken && (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      startNewChat(false);
    } else if (authToken && event.key === "/" && !typing && currentView === "chat") {
      event.preventDefault();
      $("sessionSearch").focus();
    } else if (event.key === "Escape") {
      closeAdminModal();
      closeSidebar();
    }
  });
}

function resizeComposer() {
  const input = $("chatInput");
  input.style.height = "auto";
  input.style.height = Math.min(input.scrollHeight, 190) + "px";
  $("characterCount").textContent = input.value.length + " / 2,000";
}

function setBusy(busy) {
  isSending = busy;
  $("sendBtn").disabled = busy;
  $("chatMessages").setAttribute("aria-busy", String(busy));
  $("accessNavButton").disabled = busy;
  $("directoryNavButton").disabled = busy;
  $("exploreNavButton").disabled = busy;
  $("historyNavButton").disabled = busy;
  $("scopeButton").disabled = busy;
  $("chatWorkspace").classList.toggle("is-busy", busy);
  $("newChatBtn").disabled = busy;
  $("auditNavButton").disabled = busy;
  $("adminDashboardNavButton").disabled = busy;
  $("databaseMapNavButton").disabled = busy;
  $("assistantNavButton").disabled = busy;
  document.querySelectorAll(".quick-btn,.suggestion-card,.suggestion-rail button,.session-item,.workspace-tab,.workspace-tab-close").forEach((element) => {
    element.setAttribute("aria-disabled", String(busy));
    if (element.tagName === "BUTTON") element.disabled = busy;
  });
}

function sendMessage() {
  if (isSending || currentView !== "chat") return;
  const input = $("chatInput");
  const question = input.value.trim();
  if (!question) return;
  input.value = "";
  input.style.height = "auto";
  $("characterCount").textContent = "0 / 2,000";
  submitQuestion(question);
}

async function submitQuestion(question) {
  if (isSending || currentView !== "chat") return;
  question = String(question || "").trim();
  if (!question) return;
  if (question.length > 2000) {
    showToast("Keep the question under 2,000 characters.");
    return;
  }
  if (!currentSessionId) startNewChat(true);
  closeSidebar();
  $("chatWorkspace").classList.remove("welcome-mode");
  $("chatInputArea").classList.remove("hidden");
  renderSuggestionRail(false);

  const epoch = sessionEpoch;
  const time = new Date().toISOString();
  pendingController = new AbortController();
  renderUserMessage(question, time, true);
  pushMessage({ role: "user", text: question, time: time });
  const typingId = appendTyping(question);
  setBusy(true);

  try {
    const response = await apiFetch("/chat", {
      signal: pendingController.signal,
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify({
        message: question,
        conversationId: currentSessionId,
        useContext: useChatContext,
      }),
    });
    const data = await response.json();
    removeTyping(typingId);
    if (!response.ok && !data.reply) {
      data.reply = data.error || "The request could not be completed.";
      data.status = response.status === 503 ? "unavailable" : "blocked";
    }
    const message = {
      id: newMessageId(),
      role: "bot",
      text: data.reply || "The query completed.",
      sql: data.sql || null,
      columns: Array.isArray(data.columns) ? data.columns : [],
      rows: Array.isArray(data.rows) ? data.rows : [],
      sources: Array.isArray(data.sources) ? data.sources : [],
      rowCount: Number.isFinite(Number(data.rowCount)) ? Number(data.rowCount) : (data.rows || []).length,
      durationMs: Number.isFinite(Number(data.durationMs)) ? Number(data.durationMs) : null,
      contextUsed: Number.isFinite(Number(data.contextUsed)) ? Number(data.contextUsed) : 0,
      status: data.status || "success",
      time: new Date().toISOString(),
    };
    renderBotMessage(message, true);
    pushMessage(message);
  } catch (error) {
    if (epoch !== sessionEpoch || error.name === "AbortError") return;
    removeTyping(typingId);
    const message = {
      id: newMessageId(), role: "bot",
      text: "The workspace could not be reached. Check the connection and try again.",
      status: "error", time: new Date().toISOString(), columns: [], rows: [], sources: [],
    };
    renderBotMessage(message, true);
    pushMessage(message);
  } finally {
    if (epoch === sessionEpoch) { pendingController = null; setBusy(false); }
  }
}

function renderUserMessage(text, time, animate, container) {
  const list = container || ensureMessageList();
  const row = document.createElement("article");
  row.className = "message-row user" + (animate ? "" : " no-anim");
  row.innerHTML = '<div class="message-content"><div class="user-bubble">' + escHtml(text) + '</div>' +
    '<time class="message-time" datetime="' + escHtml(time || "") + '">' + escHtml(formatTime(time)) + '</time></div>' +
    '<div class="user-avatar" aria-label="You">' + escHtml((currentUser.fullName || currentUser.username || "U")[0].toUpperCase()) + '</div>';
  list.appendChild(row);
  if (animate) scrollToBottom();
}

function ensureMessageList() {
  let list = $("chatMessages").querySelector(".message-list");
  if (!list) {
    $("chatMessages").innerHTML = '<div class="message-list"></div>';
    list = $("chatMessages").firstElementChild;
  }
  return list;
}

function appendTyping() {
  const id = "typing_" + Date.now().toString(36);
  const row = document.createElement("article");
  row.className = "message-row assistant";
  row.id = id;
  row.innerHTML = '<div class="bot-avatar">' + BOT_MARK + '</div><div class="message-content">' +
    '<div class="message-author">' + PRODUCT_NAME + '</div><div class="typing-indicator">' +
    '<span class="typing-indicator-mark" aria-hidden="true"></span><span>Thinking</span></div></div>';
  ensureMessageList().appendChild(row);
  scrollToBottom();
  return id;
}

function removeTyping(id) {
  const element = $(id);
  if (element) element.remove();
}

function renderBotMessage(message, animate, container) {
  const list = container || ensureMessageList();
  const row = document.createElement("article");
  row.className = "message-row assistant" + (animate ? "" : " no-anim");
  const safeId = escHtml(message.id || newMessageId());
  const status = message.status || "success";
  const isError = status === "error" || status === "blocked" || status === "unavailable" || status === "busy";
  const time = formatTime(message.time);
  const columns = Array.isArray(message.columns) ? message.columns : [];
  const rows = Array.isArray(message.rows) ? message.rows : [];
  const sources = Array.isArray(message.sources) ? message.sources : [];
  const rowCount = Number.isFinite(Number(message.rowCount)) ? Number(message.rowCount) : rows.length;
  let meta = "";

  if ((status === "success" || status === "partial") && (columns.length || sources.length)) {
    const parts = [];
    if (columns.length) parts.push('<span class="result-meta-item">' + rowCount + ' row' + (rowCount === 1 ? "" : "s") + '</span>');
    if (sources.length) parts.push('<span class="result-meta-item">Source: ' + escHtml(sources.join(", ")) + '</span>');
    if (Number.isFinite(Number(message.durationMs))) parts.push('<span class="result-meta-item">' + (Number(message.durationMs) / 1000).toFixed(1) + ' s</span>');
    if (message.contextUsed > 0) parts.push('<span class="result-meta-item">' + message.contextUsed + ' earlier turn' + (message.contextUsed === 1 ? '' : 's') + ' available</span>');
    meta = '<div class="result-meta">' + parts.join("") + '</div>';
  }

  let table = "";
  if (columns.length) {
    const preview = rows;
    const head = columns.map((column) => '<th scope="col">' + escHtml(column) + '</th>').join("");
    const body = preview.map((values) =>
      '<tr>' + columns.map((column, index) => {
        const value = values && values[index] !== undefined ? values[index] : null;
        const numeric = value !== null && /^-?(?:\d+|\d{1,3}(?:,\d{3})+)(?:\.\d+)?$/.test(String(value));
        const display = numeric ? formatNumericCell(value) : value === null ? "-" : String(value);
        return '<td' + (numeric ? ' class="numeric"' : '') + '>' + escHtml(display) + '</td>';
      }).join("") + '</tr>'
    ).join("");
    const content = rows.length
      ? '<div class="table-scroll"><table class="result-table"><thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table></div>' +
        '<div class="result-footnote">Showing ' + rows.length + ' of ' + rowCount + ' returned row' + (rowCount === 1 ? "" : "s") + '.</div>'
      : '<div class="result-empty">No records matched those filters.</div>';
    table = '<section class="result-block" aria-label="Query results"><div class="result-toolbar">' +
      '<span class="result-heading">Source rows</span><div class="result-actions">' +
      '<button class="result-action" type="button" data-action="copy-rows" data-message-id="' + safeId + '">' +
      '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><rect x="7" y="6" width="9" height="11" rx="1.5" stroke="currentColor" stroke-width="1.35"/><path d="M12 6V4.5A1.5 1.5 0 0 0 10.5 3h-6A1.5 1.5 0 0 0 3 4.5v8A1.5 1.5 0 0 0 4.5 14H7" stroke="currentColor" stroke-width="1.35"/></svg>Copy rows</button>' +
      '<button class="result-action" type="button" data-action="export-rows" data-message-id="' + safeId + '">' +
      '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M10 3v9m0 0 3-3m-3 3L7 9m-3 5v3h12v-3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>CSV</button>' +
      '</div></div>' + content + '</section>';
  }

  let query = "";
  if (message.sql) {
    query = '<details class="query-details"><summary>Inspect query' +
      '<span class="query-source-count">' + (sources.length ? escHtml(sources.join(", ")) : "read-only query") + '</span></summary>' +
      '<div class="sql-code-wrap"><pre class="sql-code"><code>' + escHtml(message.sql) + '</code></pre>' +
      '<div class="query-copy"><button class="result-action" type="button" data-action="copy-sql" data-message-id="' + safeId + '">' +
      '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><rect x="7" y="6" width="9" height="11" rx="1.5" stroke="currentColor" stroke-width="1.35"/><path d="M12 6V4.5A1.5 1.5 0 0 0 10.5 3h-6A1.5 1.5 0 0 0 3 4.5v8A1.5 1.5 0 0 0 4.5 14H7" stroke="currentColor" stroke-width="1.35"/></svg>Copy SQL</button></div></div></details>';
  }

  const metricIndex = columns.findIndex((column, index) =>
    /budget|revenue|total|amount|balance|count|salary|headcount/i.test(column) &&
    rows.length === 1 && rows[0][index] !== null && /^-?\d+(\.\d+)?$/.test(String(rows[0][index])));
  const metricContext = metricIndex >= 0 && rows[0]
    ? columns.map((column, index) => index === metricIndex || rows[0][index] === null ? "" : String(rows[0][index])).filter(Boolean)
    : [];
  const metricLabel = [...metricContext, ...(metricIndex >= 0 ? [columns[metricIndex].replace(/([a-z])([A-Z])/g, "$1 $2")] : [])].join(" · ");
  const metric = (status === "success" || status === "partial") && rows.length === 1 && columns.length <= 3 && metricIndex >= 0
    ? '<div class="metric-answer"><small>' + escHtml(metricLabel) + '</small><strong>' + escHtml(formatNumericCell(rows[0][metricIndex])) +
      '</strong><div class="metric-insight">' + formatReply(message.text) + '</div></div>' : '';
  const body = isError
    ? '<div class="status-message error">' + formatReply(message.text) + '</div>'
    : metric ? '' : '<div class="answer-copy">' + formatReply(message.text) + '</div>';
  row.innerHTML = '<div class="bot-avatar">' + BOT_MARK + '</div><div class="message-content">' +
    '<div class="message-author">' + PRODUCT_NAME + ' <time datetime="' + escHtml(message.time || "") + '">' + escHtml(time) + '</time></div>' +
    metric + body + meta + table + query +
    '<div class="answer-actions"><button class="result-action" type="button" data-action="copy-answer" data-message-id="' + safeId + '">Copy answer</button>' +
    (status === "busy" ? '<button class="result-action" type="button" data-action="retry-question" data-message-id="' + safeId + '">Try again</button>' :
      (isError || status === "needs_context" ? '<button class="result-action" type="button" data-action="revise-question" data-message-id="' + safeId + '">Revise question</button>' : '')) + '</div></div>';
  list.appendChild(row);
  if (animate) scrollToBottom();
}

function handleWorkspaceClick(event) {
  const remove = event.target.closest("[data-delete-session]");
  if (remove) {
    event.stopPropagation();
    deleteSession(remove.dataset.deleteSession);
    return;
  }
  const adminButton = event.target.closest("[data-admin-action]");
  if (adminButton) {
    handleAdminAction(adminButton);
    return;
  }
  const button = event.target.closest("[data-action]");
  if (!button) return;
  if (button.dataset.action === "view-access") return renderAccess();
  if (button.dataset.action === "refresh-directory") return loadDirectory();
  if (button.dataset.action === "export-audit" && !access.canAudit) return;
  if (button.dataset.action === "export-audit") {
    const fields = ["LogID", "Username", "UserRole", "Question", "ExecutionStatus", "RowsReturned", "LoggedAt"];
    downloadCsv(fields, auditRecords.map((record) => fields.map((field) => record[field])), "meridian-audit-log.csv");
    return;
  }
  const message = activeMessages.find((item) => item.id === button.dataset.messageId);
  if (!message) return;
  if (button.dataset.action === "copy-answer") copyText(message.text || "", "Answer copied.");
  else if (button.dataset.action === "retry-question") {
    const index = activeMessages.indexOf(message);
    const question = activeMessages.slice(0, index).reverse().find((item) => item.role === "user");
    if (question) submitQuestion(question.text);
  }
  else if (button.dataset.action === "revise-question") {
    const index = activeMessages.indexOf(message);
    const question = activeMessages.slice(0, index).reverse().find((item) => item.role === "user");
    if (question) { $("chatInput").value = question.text; resizeComposer(); $("chatInput").focus(); }
  }
  else if (button.dataset.action === "copy-sql") copyText(message.sql || "", "SQL copied.");
  else if (button.dataset.action === "copy-rows") copyText(rowsAsText(message.columns, message.rows), "Rows copied.");
  else if (button.dataset.action === "export-rows") downloadCsv(message.columns, message.rows, "meridian-results.csv");
}

function handleWorkspaceInput(event) {
  if (event.target.id === "auditSearch") renderAuditRows(event.target.value);
  if (event.target.id === "sourceSearch") filterSources(event.target.value);
  if (event.target.id === "directorySearch") renderDirectoryRows(event.target.value);
  if (event.target.id === "databaseMapSearch" || event.target.id === "databaseMapGroup") {
    const detail = $("databaseDetail");
    if (detail) delete detail.dataset.sourceName;
    renderDatabaseMapCanvas();
  }
}

function rowsAsText(columns, rows) {
  return [columns.join("\t")].concat((rows || []).map((row) =>
    (row || []).map((value) => value == null ? "" : String(value)).join("\t")
  )).join("\n");
}

async function copyText(value, successMessage) {
  try {
    await navigator.clipboard.writeText(value);
    showToast(successMessage);
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    const copied = document.execCommand("copy");
    textarea.remove();
    showToast(copied ? successMessage : "Copy was blocked by the browser.");
  }
}

function csvCell(value) {
  let text = value == null ? "" : String(value);
  if (/^[\t\r\n ]*[=+@]/.test(text) || (/^-/.test(text) && !/^-?\d+(\.\d+)?$/.test(text))) text = "'" + text;
  return '"' + text.replace(/"/g, '""') + '"';
}

function downloadCsv(columns, rows, filename) {
  if (!columns || !columns.length) {
    showToast("There are no rows to export.");
    return;
  }
  const lines = [columns.map(csvCell).join(",")].concat(
    (rows || []).map((row) => columns.map((column, index) => csvCell(row ? row[index] : null)).join(","))
  );
  const blob = new Blob(["\ufeff" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  showToast("CSV downloaded.");
}

function formatReply(text) {
  const codeDelimiter = String.fromCharCode(96);
  const inlineCode = new RegExp(codeDelimiter + "([^" + codeDelimiter + "]+)" + codeDelimiter, "g");
  const formatInline = (value) => escHtml(value)
    .replace(inlineCode, "<code>$1</code>")
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
  const lines = String(text == null ? "" : text).replace(/\r/g, "").split("\n");
  const output = [];
  let list = [];
  const flushList = () => {
    if (!list.length) return;
    output.push("<ul>" + list.map((item) => "<li>" + formatInline(item) + "</li>").join("") + "</ul>");
    list = [];
  };
  lines.forEach((line) => {
    const bullet = line.match(/^\s*[-*]\s+(.+)$/);
    if (bullet) { list.push(bullet[1]); return; }
    flushList();
    if (line.trim()) output.push("<p>" + formatInline(line.trim()) + "</p>");
  });
  flushList();
  return output.join("");
}

function escHtml(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function scrollToBottom() {
  const container = $("chatMessages");
  requestAnimationFrame(() => { container.scrollTop = container.scrollHeight; });
}

function openSidebar() {
  $("chatScreen").classList.add("sidebar-open");
  $("mobileSidebarOpen").setAttribute("aria-expanded", "true");
  $("mobileSidebarClose").focus();
}

function closeSidebar() {
  const wasOpen = $("chatScreen").classList.contains("sidebar-open");
  $("chatScreen").classList.remove("sidebar-open");
  $("mobileSidebarOpen").setAttribute("aria-expanded", "false");
  if (wasOpen) $("mobileSidebarOpen").focus();
}

async function loadAudit() {
  if (isSending || !access.canAudit) return;
  currentView = "audit";
  $("auditNavButton").classList.add("active");
  document.querySelectorAll(".workspace-nav .nav-link").forEach((el) => el.classList.toggle("active", el.id === "auditNavButton"));
  $("chatInputArea").classList.add("hidden");
  $("chatWorkspace").classList.remove("welcome-mode");
  renderSuggestionRail(false);
  $("clearChatBtn").classList.add("hidden");
  $("chatSubtitle").textContent = "Administration";
  $("chatSessionTitle").textContent = "Audit log";
  $("chatMessages").innerHTML = '<div class="audit-empty">Loading recent query activity...</div>';
  closeSidebar();
  try {
    const response = await apiFetch("/audit", {
      headers: { "X-CSRF-Token": csrfToken },
      cache: "no-store",
    });
    const data = await response.json();
    if (!response.ok || !Array.isArray(data)) {
      $("chatMessages").innerHTML = '<div class="status-message error">' + escHtml(data.error || "The audit log is unavailable.") + '</div>';
      return;
    }
    auditRecords = data;
    if (authToken && currentView === "audit") renderAudit();
  } catch (error) {
    if (error.name === "AbortError") return;
    $("chatMessages").innerHTML = '<div class="status-message error">The audit log could not be reached. Check the connection and try again.</div>';
  }
}

function renderAudit() {
  $("chatMessages").innerHTML =
    '<section class="audit-view" aria-labelledby="auditTitle">' +
      '<header class="audit-view-header"><div><p class="eyebrow"><span class="eyebrow-rule"></span>Administration</p>' +
      '<h2 id="auditTitle">Recent query activity</h2><p>Up to 100 recent requests from the server audit log.</p></div>' +
      '<div class="audit-tools"><input class="audit-search" id="auditSearch" type="search" placeholder="Filter activity" aria-label="Filter audit activity">' +
      '<button class="result-action" type="button" data-action="export-audit">Download CSV</button></div></header>' +
      '<div id="auditTableMount"></div></section>';
  renderAuditRows("");
}

function renderAuditRows(filter) {
  const mount = $("auditTableMount");
  if (!mount) return;
  const needle = String(filter || "").trim().toLowerCase();
  const filtered = auditRecords.filter((record) => Object.values(record).join(" ").toLowerCase().includes(needle));
  if (!filtered.length) {
    mount.innerHTML = '<div class="audit-table-wrap"><div class="audit-empty">' +
      (needle ? "No audit entries match this filter." : "No query activity has been recorded yet.") + '</div></div>';
    return;
  }
  const rows = filtered.map((record) => {
    const status = String(record.ExecutionStatus || "Unknown").toLowerCase();
    return '<tr><td>' + escHtml(record.LoggedAt || "") + '</td><td>' + escHtml(record.Username || "") +
      '</td><td>' + escHtml(record.UserRole || "") + '</td><td class="audit-question">' + escHtml(record.Question || "") +
      '</td><td><span class="audit-status ' + escHtml(status) + '">' + escHtml(record.ExecutionStatus || "Unknown") +
      '</span></td><td class="numeric">' + escHtml(record.RowsReturned || "0") + '</td></tr>';
  }).join("");
  mount.innerHTML = '<div class="audit-table-wrap"><table class="audit-table"><thead><tr>' +
    '<th scope="col">Time</th><th scope="col">User</th><th scope="col">Role</th><th scope="col">Question</th>' +
    '<th scope="col">Outcome</th><th scope="col">Rows</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
}

function showToast(message) {
  const region = $("toastRegion");
  if (!region) return;
  region.innerHTML = '<div class="toast">' + escHtml(message) + '</div>';
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { region.innerHTML = ""; }, 3000);
}

function endSession(reason) {
  sessionEpoch++;
  if (pendingController) pendingController.abort();
  if (healthInterval) clearInterval(healthInterval);
  if (expiryTimer) clearTimeout(expiryTimer);
  purgeHistory();
  authToken = null; sessionId = null; csrfToken = null; access = {};
  currentUser = {}; currentSessionId = null; activeMessages = []; auditRecords = []; directoryRecords = [];
  currentView = "chat";
  $("chatMessages").replaceChildren();
  $("chatSessionsList").replaceChildren();
  $("quickQuestions").replaceChildren();
  $("chatInput").value = "";
  $("passwordInput").value = "";
  $("passwordInput").type = "password";
  $("pwToggle").setAttribute("aria-pressed", "false");
  $("pwToggle").setAttribute("aria-label", "Show password");
  $("capsLockHint").classList.add("hidden");
  $("loginError").classList.add("hidden");
  $("chatScreen").classList.remove("access-pending");
  setBusy(false);
  closeSidebar();
  showScreen("login");
  if (reason) showLoginError(reason);
}

async function logout() {
  $("logoutBtn").disabled = true;
  try {
    const response = await apiFetch("/logout", { method: "POST" });
    if (!response.ok) throw new Error("Sign-out failed");
    endSession();
  } catch (error) {
    if (error.name !== "AbortError") showToast("Sign-out could not reach the server. Try again to end this session.");
  } finally { $("logoutBtn").disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  initializeTheme();
  bindControls();
  initializeFromSession();
});


function openWorkspaceView(view, title, navId) {
  if (isSending || !authToken) return false;
  currentView = view;
  document.querySelectorAll(".workspace-nav .nav-link").forEach((el) => {
    const selected = el.id === navId;
    el.classList.toggle("active", selected);
    if (selected) el.setAttribute("aria-current", "page"); else el.removeAttribute("aria-current");
  });
  $("chatSubtitle").textContent = roleInfo().label + " workspace";
  $("chatSessionTitle").textContent = title;
  $("chatInputArea").classList.add("hidden");
  $("chatWorkspace").classList.remove("welcome-mode");
  renderSuggestionRail(false);
  $("clearChatBtn").classList.add("hidden");
  closeSidebar();
  return true;
}

function renderAccess() {
  if (!openWorkspaceView("access", "Data library", "accessNavButton")) return;
  const scope = currentUser.region || currentUser.department || (currentUser.deptId ? "Department " + currentUser.deptId : "Organization");
  $("chatMessages").innerHTML = `
    <section class="access-view" aria-labelledby="accessTitle">
      <p class="eyebrow"><span class="eyebrow-rule"></span>Your permissions</p>
      <h2 id="accessTitle">What you can query.</h2>
      <p class="view-description">Your administrator assigns your role and scope. Every request is checked against your current account access.</p>
      <dl class="access-facts">
        <div><dt>Assigned role</dt><dd>${escHtml(access.label)}</dd></div>
        <div><dt>Account assignment</dt><dd>${escHtml(scope)}</dd></div>
        <div><dt>Available sources</dt><dd>${access.sources.length}<span> data sources</span></dd></div>
      </dl>
      <div class="access-policy"><span class="policy-icon" aria-hidden="true">${BOT_MARK}</span><div><strong>${escHtml(access.description)}</strong><p>Read access · Up to ${access.maxRows} rows per answer · Exports include returned rows only</p></div></div>
      <div class="source-heading"><div><h3>Available data</h3><p>Open a source to see the fields you can use.</p></div><input id="sourceSearch" class="audit-search" type="search" placeholder="Find a source or field" aria-label="Find an available data source"></div>
      <div id="sourceCatalog" class="source-catalog"></div>
      <p class="access-note">Need a different scope? Contact your workspace administrator. Changes to your role, department or region end your current session.</p>
    </section>`;
  filterSources("");
}

async function readJsonResponse(response, fallback) {
  try { return await response.json(); }
  catch { throw new Error(fallback + " (HTTP " + response.status + ")."); }
}

function formatNumericCell(value) {
  const raw = String(value == null ? "" : value).replace(/,/g, "");
  const match = raw.match(/^(-?)(\d+)(\.\d+)?$/);
  if (!match) return value == null ? "-" : String(value);
  let integer;
  try { integer = BigInt(match[2]).toLocaleString(); }
  catch { integer = match[2].replace(/\B(?=(\d{3})+(?!\d))/g, ","); }
  return (match[1] || "") + integer + (match[3] || "");
}

function renderExplore() {
  if (!openWorkspaceView("explore", "Explore", "exploreNavButton")) return;
  const suggestions = questions();
  const items = suggestions.map((question, index) =>
    '<button type="button" class="explore-question" data-explore-question="' + escHtml(question) + '">' +
      '<span class="explore-question-index">' + String(index + 1).padStart(2, "0") + '</span>' +
      '<span>' + escHtml(question) + '</span>' +
      '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M4 10h11m-4-4 4 4-4 4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
    '</button>'
  ).join("");
  $("chatMessages").innerHTML =
    '<section class="explore-view" aria-labelledby="exploreTitle">' +
      '<p class="eyebrow"><span class="eyebrow-rule"></span>Suggested questions</p>' +
      '<h2 id="exploreTitle">Explore your data.</h2>' +
      '<p class="view-description">Questions based on the data available to your role.</p>' +
      '<div class="explore-questions">' + items + '</div>' +
    '</section>';
}

function handleExploreClick(event) {
  const questionButton = event.target.closest("[data-explore-question]");
  if (!questionButton || isSending) return;
  const question = questionButton.getAttribute("data-explore-question");
  showChatWorkspace(false);
  submitQuestion(question);
}

function focusHistory() {
  if (isSending) return;
  document.querySelectorAll(".workspace-nav .nav-link").forEach((button) => {
    const selected = button.id === "historyNavButton";
    button.classList.toggle("active", selected);
    if (selected) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
  });
  $("historySection").scrollIntoView({ behavior: "smooth", block: "nearest" });
  $("sessionSearch").focus({ preventScroll: true });
}

function filterSources(value) {
  const needle = String(value).toLowerCase();
  const sources = (access.sources || []).filter((source) => (source.name + " " + source.columns.join(" ")).toLowerCase().includes(needle));
  $("sourceCatalog").innerHTML = sources.length ? sources.map((source, index) => `
    <details class="source-item"><summary><span class="source-index">${String(index + 1).padStart(2, "0")}</span><span class="source-name">${escHtml(source.name.replace(/^v_/, "").replace(/([a-z])([A-Z])/g, "$1 $2"))}<small>${escHtml(source.name)}</small></span><span class="scope-tag">${escHtml(source.scope)}</span><span class="source-toggle" aria-hidden="true">+</span></summary>
      <div class="source-fields">${source.columns.map((column) => '<span>' + escHtml(column) + '</span>').join("")}</div>
    </details>`).join("") : '<div class="audit-empty">No sources match this search.</div>';
}

async function loadAdminDashboard() {
  if (!access.canManageUsers || !openWorkspaceView("admin-dashboard", "Overview", "adminDashboardNavButton")) return;
  $("chatMessages").innerHTML = '<div class="admin-loading">Loading workspace activity…</div>';
  try {
    const response = await apiFetch("/admin/overview");
    const data = await readJsonResponse(response, "Workspace activity is unavailable");
    if (!response.ok) throw new Error(data.error || "Workspace activity is unavailable.");
    if (currentView === "admin-dashboard") renderAdminDashboard(data);
  } catch (error) {
    if (error.name !== "AbortError" && currentView === "admin-dashboard") {
      $("chatMessages").innerHTML = '<div class="status-message error">' + escHtml(error.message) + '</div>';
    }
  }
}

function renderAdminDashboard(data) {
  adminOverview = data;
  const cards = [
    ["Active accounts", data.users.active, data.users.disabled + " disabled"],
    ["Roles", data.roles, "Access templates"],
    ["Data sources", data.sources, "Available to configure"],
    ["Requests · 30 days", data.activity.requests30d, data.activity.successful30d + " completed"],
    ["Blocked or failed", data.activity.issues30d, "Last 30 days"],
  ];
  const activityByDay = new Map(data.trend.map((item) => [String(item.Day).slice(0, 10), item]));
  const chartTrend = [];
  const today = new Date();
  today.setHours(12, 0, 0, 0);
  for (let offset = 13; offset >= 0; offset--) {
    const date = new Date(today);
    date.setDate(today.getDate() - offset);
    const key = [date.getFullYear(), String(date.getMonth() + 1).padStart(2, "0"), String(date.getDate()).padStart(2, "0")].join("-");
    const record = activityByDay.get(key) || {};
    chartTrend.push({...record, Day: key, Requests: Number(record.Requests) || 0,
      Successful: Number(record.Successful) || 0, Issues: Number(record.Issues) || 0});
  }
  const maximum = Math.max(1, ...chartTrend.map((item) => Number(item.Requests) || 0));
  const bars = chartTrend.map((item, index) => {
    const value = Number(item.Requests) || 0;
    const success = Number(item.Successful) || 0;
    const issues = Number(item.Issues) || 0;
    const height = Math.max(2, Math.round(value / maximum * 112));
    const issueHeight = value ? Math.round(issues / value * height) : 0;
    const day = new Date(String(item.Day) + "T12:00:00").toLocaleDateString(undefined, { month: "short", day: "numeric" });
    return '<g class="activity-bar" aria-label="' + escHtml(day + ": " + value + " requests") + '"><rect x="' + (index * 48 + 12) + '" y="' + (126 - height) + '" width="25" height="' + height + '" rx="3"/><rect class="activity-issue" x="' + (index * 48 + 12) + '" y="' + (126 - issueHeight) + '" width="25" height="' + issueHeight + '" rx="3"/><text x="' + (index * 48 + 24) + '" y="150">' + escHtml(day) + '</text></g>';
  }).join("");
  const recent = data.recent.length ? data.recent.map((item) =>
    '<tr><td>' + escHtml(String(item.LoggedAt || "").replace("T", " ").slice(0, 16)) + '</td><td>' + escHtml(item.Username || "") +
    '</td><td class="admin-question-cell">' + escHtml(item.Question || "") + '</td><td><span class="audit-status ' + escHtml(String(item.ExecutionStatus || "").toLowerCase()) + '">' + escHtml(item.ExecutionStatus || "Unknown") + '</span></td><td class="numeric">' + escHtml(item.RowsReturned || 0) + '</td></tr>'
  ).join("") : '<tr><td colspan="5" class="admin-empty-cell">No query activity has been recorded yet.</td></tr>';
  const securityEvents = (data.securityEvents || []).length ? data.securityEvents.map((item) =>
    '<tr><td>' + escHtml(String(item.LoggedAt || "").replace("T", " ").slice(0, 16)) + '</td><td>' + escHtml(item.ActorUsername || "System") +
    '</td><td><span class="role-label">' + escHtml(String(item.EventType || "").replaceAll(".", " · ")) + '</span></td><td>' +
    escHtml((item.TargetType || "") + " " + (item.TargetIdentifier || "")) + '</td><td class="admin-question-cell">' + escHtml(item.Details || "") + '</td></tr>'
  ).join("") : '<tr><td colspan="5" class="admin-empty-cell">No access changes have been recorded yet.</td></tr>';
  $("chatMessages").innerHTML =
    '<section class="admin-page" aria-labelledby="adminOverviewTitle">' +
      '<header class="admin-page-header"><div><p class="eyebrow">ADMINISTRATION</p><h2 id="adminOverviewTitle">Workspace overview</h2><p>Accounts, access, and query activity at a glance.</p></div>' +
      '<div class="admin-header-actions"><button class="admin-button secondary" data-admin-action="open-users">Manage users</button><button class="admin-button" data-admin-action="open-database-map">Open data map</button></div></header>' +
      '<div class="admin-metric-grid">' + cards.map((card) => '<article class="admin-metric"><span>' + escHtml(card[0]) + '</span><strong>' + escHtml(card[1]) + '</strong><small>' + escHtml(card[2]) + '</small></article>').join("") + '</div>' +
      '<div class="admin-dashboard-grid"><section class="admin-panel activity-panel"><div class="admin-panel-heading"><div><h3>Query activity</h3><p>Daily requests over the last 14 days</p></div><span class="chart-legend"><i></i>Requests <i class="legend-issue"></i>Blocked / failed</span></div>' +
      '<svg class="activity-chart" viewBox="0 0 ' + Math.max(520, chartTrend.length * 48) + ' 166" role="img" aria-label="Daily query request volume for the last two weeks"><line x1="0" y1="126" x2="' + Math.max(520, chartTrend.length * 48) + '" y2="126"/><line x1="0" y1="70" x2="' + Math.max(520, chartTrend.length * 48) + '" y2="70"/>' + bars + '</svg></section>' +
      '<section class="admin-panel posture-panel"><div class="admin-panel-heading"><div><h3>Access posture</h3><p>Current account distribution</p></div></div><div class="posture-row"><span>Enabled</span><strong>' + data.users.active + '</strong></div><div class="posture-meter"><i style="width:' + (data.users.total ? Math.round(data.users.active / data.users.total * 100) : 0) + '%"></i></div><div class="posture-row"><span>Disabled</span><strong>' + data.users.disabled + '</strong></div><div class="posture-row"><span>Total accounts</span><strong>' + data.users.total + '</strong></div><button class="text-action" data-admin-action="open-users">Review account scopes <span>→</span></button></section></div>' +
      '<section class="admin-panel recent-panel"><div class="admin-panel-heading"><div><h3>Recent activity</h3><p>Latest database requests</p></div><button class="text-action" data-admin-action="open-audit">Full activity log <span>→</span></button></div><div class="audit-table-wrap"><table class="audit-table admin-audit-table"><thead><tr><th>Time</th><th>User</th><th>Question</th><th>Outcome</th><th>Rows</th></tr></thead><tbody>' + recent + '</tbody></table></div></section>' +
      '<section class="admin-panel recent-panel"><div class="admin-panel-heading"><div><h3>Access change trail</h3><p>Recent administrator changes to accounts, roles, and data scopes</p></div></div><div class="audit-table-wrap"><table class="audit-table admin-audit-table"><thead><tr><th>Time</th><th>Administrator</th><th>Change</th><th>Target</th><th>Details</th></tr></thead><tbody>' + securityEvents + '</tbody></table></div></section>' +
    '</section>';
}

async function loadDatabaseMap() {
  if (!access.canViewSchema || !openWorkspaceView("database-map", "Data map", "databaseMapNavButton")) return;
  $("chatMessages").innerHTML = '<div class="admin-loading">Reading database structure…</div>';
  try {
    const response = await apiFetch("/admin/catalog");
    const data = await readJsonResponse(response, "Database structure is unavailable");
    if (!response.ok) throw new Error(data.error || "Database structure is unavailable.");
    databaseCatalog = data;
    if (currentView === "database-map") renderDatabaseMap();
  } catch (error) {
    if (error.name !== "AbortError" && currentView === "database-map") {
      $("chatMessages").innerHTML = '<div class="status-message error">' + escHtml(error.message) + '</div>';
    }
  }
}

const MAP_GROUPS = ["People & operations", "Sales", "Inventory", "Finance", "Views", "Protected system"];
const MAP_CARD_W = 244, MAP_CARD_H = 112, MAP_COL_GAP = 28, MAP_ROW_GAP = 24;

function mapSourceLabel(name) {
  const canonical = (access.sources || []).find((source) => source.name.toLowerCase() === String(name).toLowerCase());
  return canonical ? canonical.name : name;
}

function renderDatabaseMap() {
  const summary = databaseCatalog.summary || {};
  $("chatMessages").innerHTML =
    '<section class="admin-page database-map-page" aria-labelledby="databaseMapTitle">' +
      '<header class="admin-page-header"><div><p class="eyebrow">ADMINISTRATION / DATA</p><h2 id="databaseMapTitle">Database map</h2><p>Tables, fields, and relationships from the live workspace database.</p></div><div class="admin-header-actions"><button class="admin-button secondary" data-admin-action="open-roles">Configure role scopes</button></div></header>' +
      '<div class="schema-summary">' + [["Objects", summary.objects], ["Tables", summary.tables], ["Views", summary.views], ["Relationships", summary.relationships], ["Fields", summary.fields], ["Grantable", summary.grantable]].map((item) => '<div><span>' + escHtml(item[0]) + '</span><strong>' + escHtml(item[1] || 0) + '</strong></div>').join("") + '</div>' +
      '<div class="map-toolbar"><label class="admin-search-wrap"><span class="visually-hidden">Search tables and fields</span><input id="databaseMapSearch" type="search" placeholder="Find a table or field"></label><select id="databaseMapGroup" aria-label="Filter by data area"><option value="">All data areas</option>' + MAP_GROUPS.map((group) => '<option>' + escHtml(group) + '</option>').join("") + '</select><span class="map-legend"><i class="map-dot grantable"></i>Configurable <i class="map-dot protected"></i>Protected</span></div>' +
      '<div class="schema-map-viewport"><div id="schemaMapCanvas"></div></div>' +
      '<div id="databaseDetail" class="database-detail"><p>Select a table to inspect its fields and access status.</p></div>' +
    '</section>';
  renderDatabaseMapCanvas();
}

function renderDatabaseMapCanvas() {
  const canvas = $("schemaMapCanvas");
  if (!canvas) return;
  const search = String($("databaseMapSearch")?.value || "").trim().toLowerCase();
  const groupFilter = $("databaseMapGroup")?.value || "";
  const sources = databaseCatalog.sources.filter((source) =>
    (!groupFilter || source.group === groupFilter) &&
    (!search || (source.name + " " + source.group + " " + source.columns.map((column) => column.name + " " + column.type).join(" ")).toLowerCase().includes(search))
  );
  const groups = MAP_GROUPS.map((group) => ({ group, items: sources.filter((source) => source.group === group) })).filter((item) => item.items.length);
  const positions = new Map();
  groups.forEach((lane, laneIndex) => lane.items.forEach((source, rowIndex) => {
    positions.set(source.name, { x: laneIndex * (MAP_CARD_W + MAP_COL_GAP) + 18, y: rowIndex * (MAP_CARD_H + MAP_ROW_GAP) + 42 });
  }));
  const width = Math.max(1, groups.length) * (MAP_CARD_W + MAP_COL_GAP) + 24;
  const maxRows = Math.max(1, ...groups.map((lane) => lane.items.length));
  const height = maxRows * (MAP_CARD_H + MAP_ROW_GAP) + 56;
  const edgePaths = databaseCatalog.relationships.filter((edge) => positions.has(edge.fromTable) && positions.has(edge.toTable)).map((edge) => {
    const from = positions.get(edge.fromTable), to = positions.get(edge.toTable);
    const forward = to.x > from.x;
    const x1 = from.x + (forward ? MAP_CARD_W : 0), x2 = to.x + (forward ? 0 : MAP_CARD_W);
    const y1 = from.y + MAP_CARD_H / 2, y2 = to.y + MAP_CARD_H / 2;
    const bend = Math.max(34, Math.abs(x2 - x1) * .42);
    const c1 = x1 + (forward ? bend : -bend), c2 = x2 - (forward ? bend : -bend);
    const label = edge.fromColumn && edge.toColumn ? edge.fromColumn + " → " + edge.toColumn : edge.kind === "view-source" ? "derived from" : "relationship";
    return '<path class="schema-edge ' + (edge.kind === "view-source" ? "view-edge" : "") + '" d="M ' + x1 + ' ' + y1 + ' C ' + c1 + ' ' + y1 + ', ' + c2 + ' ' + y2 + ', ' + x2 + ' ' + y2 + '"><title>' + escHtml(edge.fromTable + "." + label + " → " + edge.toTable) + '</title></path>';
  }).join("");
  const lanes = groups.map((lane, laneIndex) => {
    const x = laneIndex * (MAP_CARD_W + MAP_COL_GAP) + 18;
    return '<div class="schema-lane-label" style="left:' + x + 'px">' + escHtml(lane.group) + '<span>' + lane.items.length + '</span></div>';
  }).join("");
  const cards = groups.flatMap((lane) => lane.items.map((source) => {
    const pos = positions.get(source.name);
    const columns = source.columns.slice(0, 4).map((column) => '<span class="schema-column-chip ' + (column.key ? "is-key" : "") + '">' + (column.key ? '<b>' + escHtml(column.key) + '</b>' : '') + escHtml(column.name) + '</span>').join("");
    const more = source.columns.length > 4 ? '<small>+' + (source.columns.length - 4) + ' fields</small>' : '';
    return '<button type="button" class="schema-node ' + (source.queryable ? "grantable" : "protected") + '" style="left:' + pos.x + 'px;top:' + pos.y + 'px" data-admin-action="schema-node" data-source-name="' + escHtml(source.name) + '"><span class="schema-node-top"><strong>' + escHtml(mapSourceLabel(source.name)) + '</strong><small>' + (source.type === "VIEW" ? "VIEW" : "TABLE") + '</small></span><span class="schema-columns">' + columns + '</span><span class="schema-node-foot"><span>' + source.columns.length + ' fields</span><span>' + source.relationships + ' links</span>' + (!source.queryable ? '<b>PROTECTED</b>' : '') + '</span>' + more + '</button>';
  })).join("");
  canvas.style.width = width + "px";
  canvas.style.height = height + "px";
  canvas.innerHTML = '<div class="schema-lanes">' + lanes + '</div><svg class="schema-edges" width="' + width + '" height="' + height + '" aria-hidden="true">' + edgePaths + '</svg>' + cards;
  const detail = $("databaseDetail");
  if (detail && !detail.dataset.sourceName) detail.innerHTML = '<p>' + (search || groupFilter ? "Select a matching object to inspect its fields." : "Select a table to inspect its fields and access status.") + '</p>';
}

function showSchemaDetail(name) {
  const source = databaseCatalog.sources.find((item) => item.name === name);
  const detail = $("databaseDetail");
  if (!source || !detail) return;
  detail.dataset.sourceName = source.name;
  const columns = source.columns.map((column) => '<tr><td>' + escHtml(column.name) + '</td><td><code>' + escHtml(column.type) + '</code></td><td>' + (column.key ? '<span class="schema-key-badge">' + escHtml(column.key) + '</span>' : '—') + '</td><td>' + (column.nullable ? 'Nullable' : 'Required') + '</td></tr>').join("");
  detail.innerHTML = '<div class="database-detail-head"><div><span class="schema-type-label">' + escHtml(source.type.replace("BASE ", "")) + (source.queryable ? " · QUERYABLE" : " · PROTECTED") + '</span><h3>' + escHtml(mapSourceLabel(source.name)) + '</h3><p>' + source.columns.length + ' fields · ' + source.relationships + ' relationships · ' + escHtml(source.group) + '</p></div>' + (source.queryable ? '<button class="text-action" data-admin-action="open-roles">Edit role access <span>→</span></button>' : '') + '</div><div class="audit-table-wrap"><table class="audit-table schema-field-table"><thead><tr><th>Field</th><th>Type</th><th>Key</th><th>Nullability</th></tr></thead><tbody>' + columns + '</tbody></table></div>' + (!source.queryable ? '<p class="access-note">This object is a protected application table and cannot be granted to chat roles.</p>' : '');
  document.querySelectorAll(".schema-node").forEach((node) => node.classList.toggle("selected", node.dataset.sourceName === source.name));
}

async function loadDirectory(tab = adminDirectoryTab) {
  if ((!access.canManageUsers && !access.canManageRoles) || !openWorkspaceView("directory", "Users & roles", "directoryNavButton")) return;
  adminDirectoryTab = tab === "roles" && access.canManageRoles ? "roles" : "users";
  $("chatMessages").innerHTML = '<div class="admin-loading" role="status">Loading accounts and access rules…</div>';
  try {
    const jobs = [];
    if (access.canManageUsers) jobs.push(apiFetch("/admin/users").then(async (response) => {
      const data = await readJsonResponse(response, "The account directory is unavailable");
      if (!response.ok) throw new Error(data.error || "The account directory is unavailable.");
      adminUsersPayload = data;
    }));
    if (access.canManageRoles) jobs.push(apiFetch("/admin/roles").then(async (response) => {
      const data = await readJsonResponse(response, "Role scopes are unavailable");
      if (!response.ok) throw new Error(data.error || "Role scopes are unavailable.");
      adminRolesPayload = data;
    }));
    await Promise.all(jobs);
    if (currentView === "directory" && authToken) renderAdminDirectory();
  } catch (error) {
    if (error.name !== "AbortError" && currentView === "directory") $("chatMessages").innerHTML = '<div class="status-message error">' + escHtml(error.message) + '</div>';
  }
}

function renderAdminDirectory() {
  const users = adminUsersPayload.users || [];
  const roles = access.canManageRoles ? (adminRolesPayload.roles || []) : (adminUsersPayload.roles || []);
  const active = users.filter((item) => Boolean(item.IsActive)).length;
  const disabled = users.length - active;
  const customRoles = roles.filter((item) => item.scopeMode === "custom").length;
  const canUsers = Boolean(access.canManageUsers);
  const canRoles = Boolean(access.canManageRoles);
  $("chatMessages").innerHTML =
    '<section class="admin-page" aria-labelledby="directoryTitle">' +
      '<header class="admin-page-header"><div><p class="eyebrow">ADMINISTRATION / IDENTITY</p><h2 id="directoryTitle">Users &amp; roles</h2><p>Manage accounts, assignments, and exactly which business fields each person can query.</p></div>' +
      '<div class="admin-header-actions">' + (canRoles ? '<button class="admin-button secondary" data-admin-action="new-role">Create role</button>' : '') + (canUsers ? '<button class="admin-button" data-admin-action="new-user">Add user</button>' : '') + '</div></header>' +
      '<div class="admin-metric-grid directory-metrics">' +
        '<article class="admin-metric"><span>Accounts</span><strong>' + users.length + '</strong><small>Directory total</small></article>' +
        '<article class="admin-metric"><span>Active</span><strong>' + active + '</strong><small>Can sign in</small></article>' +
        '<article class="admin-metric"><span>Disabled</span><strong>' + disabled + '</strong><small>Sign-in blocked</small></article>' +
        '<article class="admin-metric"><span>Roles</span><strong>' + roles.length + '</strong><small>' + customRoles + ' with configured scopes</small></article>' +
        '<article class="admin-metric"><span>Departments</span><strong>' + (adminUsersPayload.departments || []).length + '</strong><small>Assignment options</small></article>' +
      '</div>' +
      '<nav class="admin-switcher" aria-label="Identity administration">' +
        (canUsers ? '<button type="button" data-admin-action="directory-users" class="' + (adminDirectoryTab === "users" ? "active" : "") + '" aria-pressed="' + (adminDirectoryTab === "users") + '">People</button>' : '') +
        (canRoles ? '<button type="button" data-admin-action="directory-roles" class="' + (adminDirectoryTab === "roles" ? "active" : "") + '" aria-pressed="' + (adminDirectoryTab === "roles") + '">Roles &amp; scopes</button>' : '') +
      '</nav>' +
      '<div class="directory-toolbar"><label class="admin-search-wrap"><span class="visually-hidden">Filter directory</span><input id="directorySearch" type="search" placeholder="' + (adminDirectoryTab === "users" ? "Search name, username, role, or assignment" : "Search role name or source") + '"></label>' +
      '<span class="toolbar-spacer"></span><button class="admin-button secondary" data-admin-action="refresh-directory">Refresh</button>' +
      (adminDirectoryTab === "users" && canUsers ? '<button class="admin-button" data-admin-action="new-user">Add user</button>' : '') +
      (adminDirectoryTab === "roles" && canRoles ? '<button class="admin-button" data-admin-action="new-role">Create role</button>' : '') + '</div>' +
      '<div id="directoryTable"></div>' +
      '<p class="access-note">Scope changes revoke existing sessions. A user-specific scope can only narrow the permissions of the assigned role. The administrator role remains protected.</p>' +
    '</section>';
  renderDirectoryRows("");
}

function renderDirectoryRows(value) {
  const mount = $("directoryTable");
  if (!mount) return;
  const needle = String(value || "").trim().toLowerCase();
  if (adminDirectoryTab === "roles") {
    const roles = (access.canManageRoles ? adminRolesPayload.roles : adminUsersPayload.roles) || [];
    const rows = roles.filter((item) => [item.RoleName, item.Description, ...(item.sources || []).map((source) => source.name)].join(" ").toLowerCase().includes(needle));
    mount.innerHTML = rows.length ? '<div class="audit-table-wrap"><table class="audit-table directory-table"><thead><tr><th>Role</th><th>Description</th><th>Data scope</th><th>Sources</th><th>People</th><th></th></tr></thead><tbody>' + rows.map((item) => {
      const locked = Boolean(item.locked);
      const mode = item.scopeMode === "custom" ? "Configured scope" : "Server policy";
      return '<tr><td><strong class="person-name">' + escHtml(item.RoleName) + '</strong><span class="person-meta">ID ' + escHtml(item.RoleID) + '</span></td><td class="role-description-cell">' + escHtml(item.Description || "No description") + '</td><td><span class="role-mode-badge ' + (item.scopeMode === "custom" ? "" : "policy") + '">' + mode + '</span></td><td>' + (item.sources || []).length + ' sources</td><td>' + escHtml(item.UserCount || 0) + '</td><td><div class="admin-row-actions">' + (locked ? '<span class="person-meta">Protected</span>' : (access.canManageRoles ? '<button type="button" data-admin-action="edit-role" data-role-id="' + escHtml(item.RoleID) + '">Edit scope</button>' : '')) + '</div></td></tr>';
    }).join("") + '</tbody></table></div>' : '<div class="audit-empty">No roles match this search.</div>';
    return;
  }
  const rows = (adminUsersPayload.users || []).filter((item) => [item.FullName, item.Username, item.Role, item.Department, item.Region].join(" ").toLowerCase().includes(needle));
  mount.innerHTML = rows.length ? '<div class="audit-table-wrap"><table class="audit-table directory-table"><thead><tr><th>Person</th><th>Role</th><th>Assignment</th><th>Last sign-in</th><th>Account</th><th></th></tr></thead><tbody>' + rows.map((item) => {
    const enabled = Boolean(item.IsActive);
    const assign = [item.Department, item.Region].filter(Boolean).join(" · ") || "Organization";
    const lastLogin = item.LastLogin ? formatRelativeDate(item.LastLogin) : "Never";
    return '<tr><td><strong class="person-name">' + escHtml(item.FullName) + '</strong><span class="person-meta">' + escHtml(item.Username) + '</span></td><td><span class="role-label">' + escHtml(item.Role) + '</span></td><td>' + escHtml(assign) + '</td><td>' + escHtml(lastLogin) + '</td><td><span class="audit-status ' + (enabled ? "success" : "blocked") + '">' + (enabled ? "Active" : "Disabled") + '</span></td><td><div class="admin-row-actions"><button type="button" data-admin-action="user-scope" data-user-id="' + escHtml(item.UserID) + '">Data scope</button><button type="button" data-admin-action="edit-user" data-user-id="' + escHtml(item.UserID) + '">Edit</button></div></td></tr>';
  }).join("") + '</tbody></table></div>' : '<div class="audit-empty">No accounts match this search.</div>';
}

function openAdminModal(formKind, title, description, body, submitLabel, wide = false) {
  const root = $("modalRoot");
  root.innerHTML = '<div class="admin-modal-backdrop" data-admin-backdrop><section class="admin-modal' + (wide ? ' wide' : '') + '" role="dialog" aria-modal="true" aria-labelledby="adminModalTitle"><header class="admin-modal-head"><div><h2 id="adminModalTitle">' + escHtml(title) + '</h2><p>' + escHtml(description) + '</p></div><button class="admin-modal-close" type="button" data-admin-action="close-modal" aria-label="Close dialog">×</button></header><form class="admin-form-shell" data-modal-form="' + escHtml(formKind) + '"><div class="admin-modal-body"><div class="modal-error hidden" role="alert"></div>' + body + '</div><footer class="admin-modal-foot"><button type="button" class="admin-button secondary" data-admin-action="close-modal">Cancel</button><button type="submit" class="admin-button">' + escHtml(submitLabel) + '</button></footer></form></section></div>';
  const focus = root.querySelector('input:not([type="checkbox"]),select,textarea');
  if (focus) setTimeout(() => focus.focus(), 0);
}

function closeAdminModal() { $("modalRoot").replaceChildren(); }

function optionsForRole(selectedId) {
  const roles = adminUsersPayload.roles || [];
  return '<option value="">Choose a role</option>' + roles.map((role) => '<option value="' + escHtml(role.RoleID) + '" ' + (String(role.RoleID) === String(selectedId || "") ? "selected" : "") + '>' + escHtml(role.RoleName) + '</option>').join("");
}

function optionsForDepartment(selectedId) {
  const departments = adminUsersPayload.departments || [];
  return '<option value="">No department</option>' + departments.map((item) => '<option value="' + escHtml(item.id) + '" ' + (String(item.id) === String(selectedId || "") ? "selected" : "") + '>' + escHtml(item.name) + '</option>').join("");
}

function openUserModal(userId = null) {
  if (!access.canManageUsers) return;
  const item = userId == null ? null : (adminUsersPayload.users || []).find((record) => Number(record.UserID) === Number(userId));
  if (userId != null && !item) return showToast("That account is no longer in the directory.");
  const body = '<div class="admin-form">' +
    '<div class="admin-field"><label for="adminFullName">Full name</label><input id="adminFullName" name="fullName" maxlength="100" required value="' + escHtml(item?.FullName || "") + '"></div>' +
    '<div class="admin-field"><label for="adminUsername">Username</label><input id="adminUsername" name="username" minlength="3" maxlength="50" pattern="[A-Za-z0-9_.-]+" required value="' + escHtml(item?.Username || "") + '"></div>' +
    '<div class="admin-field"><label for="adminRole">Role</label><select id="adminRole" name="roleId" required>' + optionsForRole(item?.RoleID) + '</select></div>' +
    '<div class="admin-field"><label for="adminDepartment">Department</label><select id="adminDepartment" name="deptId">' + optionsForDepartment(item?.DeptID) + '</select></div>' +
    '<div class="admin-field"><label for="adminRegion">Region</label><input id="adminRegion" name="region" maxlength="50" value="' + escHtml(item?.Region || "") + '" placeholder="For region-scoped access"></div>' +
    '<div class="admin-field"><label for="adminStatus">Account status</label><select id="adminStatus" name="isActive"><option value="true" ' + (item?.IsActive !== false && item?.IsActive !== 0 ? "selected" : "") + '>Active</option><option value="false" ' + (item && (item.IsActive === false || item.IsActive === 0) ? "selected" : "") + '>Disabled</option></select></div>' +
    (!item ? '<div class="admin-field full"><label for="adminPassword">Temporary password</label><input id="adminPassword" name="password" type="password" minlength="12" maxlength="256" autocomplete="new-password" required><span class="admin-help">Use 12 or more characters. The password is stored as a one-way hash.</span></div>' : '<div class="admin-field full"><label for="adminPassword">Set a new password <span class="admin-help">(optional)</span></label><input id="adminPassword" name="password" type="password" minlength="12" maxlength="256" autocomplete="new-password" placeholder="Leave blank to keep the current password"></div>') +
    '<div class="admin-field full"><span class="admin-help">Sales roles require a region. Finance roles require a department. Saving account changes signs the user out of existing sessions.</span></div>' +
    '</div>';
  openAdminModal(item ? "user-edit" : "user-create", item ? "Edit account" : "Create account", "Set the account identity and its role assignment.", body, item ? "Save account" : "Create account");
  if (item) $("adminPassword").removeAttribute("required");
}

function grantsFromRole(role) {
  return (role?.sources || []).map((item) => ({name: item.name, allColumns: false, columns: item.columns || []}));
}

function renderGrantList(catalog, selected, disabled = false) {
  const grants = new Map((selected || []).map((item) => [String(item.name).toLowerCase(), item]));
  return '<div class="grant-list">' + (catalog || []).map((source) => {
    const grant = grants.get(source.name.toLowerCase());
    const enabled = Boolean(grant);
    const all = enabled && (grant.allColumns === true || ((grant.columns || []).length === source.columns.length && source.columns.length > 0));
    const chosen = new Set((grant?.columns || []).map((column) => String(column).toLowerCase()));
    const columns = (source.columns || []).map((column) => '<label class="grant-column" title="' + escHtml(column) + '"><input type="checkbox" data-grant-column value="' + escHtml(column) + '" ' + (all || chosen.has(column.toLowerCase()) ? "checked" : "") + (disabled || !enabled || all ? " disabled" : "") + '>' + escHtml(column) + '</label>').join("");
    return '<section class="grant-source-card ' + (enabled ? "" : "is-disabled") + '" data-grant-source="' + escHtml(source.name) + '"><div class="grant-source-head"><label class="grant-source-name"><input type="checkbox" data-grant-enabled ' + (enabled ? "checked" : "") + (disabled ? " disabled" : "") + '><span>' + escHtml(source.name) + '</span></label><label class="grant-source-all"><input type="checkbox" data-grant-all ' + (all ? "checked" : "") + (disabled || !enabled ? " disabled" : "") + '> All fields</label><span class="grant-field-count">' + source.columns.length + ' fields</span></div><div class="grant-columns">' + columns + '</div></section>';
  }).join("") + '</div>';
}

function syncGrantCard(card) {
  if (!card) return;
  const enabled = card.querySelector("[data-grant-enabled]")?.checked;
  const all = card.querySelector("[data-grant-all]")?.checked;
  card.classList.toggle("is-disabled", !enabled);
  card.querySelectorAll("[data-grant-all]").forEach((input) => { input.disabled = !enabled; });
  card.querySelectorAll("[data-grant-column]").forEach((input) => { input.disabled = !enabled || all; });
}

function gatherGrantList(root) {
  const grants = [];
  for (const card of root.querySelectorAll("[data-grant-source]")) {
    if (!card.querySelector("[data-grant-enabled]")?.checked) continue;
    const allColumns = Boolean(card.querySelector("[data-grant-all]")?.checked);
    const columns = allColumns ? [] : [...card.querySelectorAll("[data-grant-column]:checked")].map((input) => input.value);
    if (!allColumns && !columns.length) throw new Error("Select at least one field for " + card.dataset.grantSource + ".");
    grants.push({name: card.dataset.grantSource, allColumns, columns});
  }
  return grants;
}

async function openRoleModal(roleId = null) {
  if (!access.canManageRoles) return;
  const role = roleId == null ? null : (adminRolesPayload.roles || []).find((item) => Number(item.RoleID) === Number(roleId));
  if (roleId != null && !role) return showToast("That role is no longer available.");
  const catalog = role ? (role.baseSources || adminRolesPayload.catalog || []) : (adminRolesPayload.catalog || []);
  const builtIn = Boolean(role?.baseSources?.length && role.RoleName in {sales:1, inventory:1, finance:1, hr:1, management:1});
  const hint = builtIn
    ? "Built-in role boundaries and row filters are preserved. Choose a subset of its approved data and fields."
    : "The role can query only selected tables and columns. Safe row filters such as region and department remain enforced for protected built-in roles.";
  const body = '<div class="admin-form"><div class="admin-field"><label for="adminRoleName">Role key</label><input id="adminRoleName" name="name" minlength="2" maxlength="50" pattern="[A-Za-z][A-Za-z0-9_-]*" required value="' + escHtml(role?.RoleName || "") + '" ' + (role ? "readonly" : "") + '><span class="admin-help">Use a unique key, such as operations_analyst.</span></div><div class="admin-field"><label for="adminRoleDescription">Description</label><input id="adminRoleDescription" name="description" maxlength="200" value="' + escHtml(role?.Description || "") + '"></div><div class="admin-field full"><span class="field-label">Queryable sources and fields</span><span class="admin-help">' + escHtml(hint) + '</span></div><div class="admin-field full">' + renderGrantList(catalog, grantsFromRole(role)) + '</div></div>';
  openAdminModal(role ? "role-edit" : "role-create", role ? "Configure role scope" : "Create role", "Select the business data this role is allowed to query.", body, role ? "Save role" : "Create role", true);
  selectedRoleId = role ? role.RoleID : null;
  $("adminRoleName")?.focus();
  $("modalRoot").querySelectorAll("[data-grant-source]").forEach(syncGrantCard);
}

async function openUserScopeModal(userId) {
  if (!access.canManageUsers) return;
  const item = (adminUsersPayload.users || []).find((record) => Number(record.UserID) === Number(userId));
  if (!item) return showToast("That account is no longer in the directory.");
  try {
    const response = await apiFetch("/admin/users/" + encodeURIComponent(userId) + "/data-access");
    const data = await readJsonResponse(response, "This account's scope could not be loaded");
    if (!response.ok) throw new Error(data.error || "This account's scope could not be loaded.");
    userScopePayload = data;
    const inherited = data.mode !== "custom";
    const selection = inherited ? (data.roleSources || []).map((source) => ({name: source.name, allColumns: true, columns: []})) : (data.sources || []);
    const body = '<div class="grant-mode-control"><div><strong>' + escHtml(item.FullName) + ' · ' + escHtml(item.Role) + '</strong><p>Custom access can only remove sources or fields granted to this role.</p></div><label class="admin-field"><span class="field-label">Scope</span><select id="userScopeMode" ' + (data.locked ? "disabled" : "") + '><option value="inherit" ' + (inherited ? "selected" : "") + '>Use role access</option><option value="custom" ' + (!inherited ? "selected" : "") + '>Limit this user</option></select></label></div>' +
      (data.locked ? '<p class="grant-lock-note">Administrator access is protected and always follows the server-managed administrator policy.</p>' : '<div id="userGrantList">' + renderGrantList(data.roleSources || [], selection, inherited) + '</div>');
    openAdminModal("user-scope", "User data scope", "Review or limit the data available to this account.", body, data.locked ? "Close" : "Save access", true);
    $("modalRoot").querySelectorAll("[data-grant-source]").forEach(syncGrantCard);
    if (data.locked) $("modalRoot").querySelector('[data-modal-form]').dataset.modalForm = "scope-locked";
  } catch (error) {
    if (error.name !== "AbortError") showToast(error.message);
  }
}

function handleAdminModalChange(event) {
  const target = event.target;
  if (!target) return;
  if (target.matches("[data-grant-enabled], [data-grant-all]")) {
    const card = target.closest("[data-grant-source]");
    if (target.matches("[data-grant-enabled]") && target.checked) {
      const columns = [...card.querySelectorAll("[data-grant-column]")];
      if (!columns.some((input) => input.checked)) columns.forEach((input) => { input.checked = true; });
    }
    syncGrantCard(card);
    return;
  }
  if (target.id === "userScopeMode") {
    const custom = target.value === "custom";
    $("modalRoot").querySelectorAll("[data-grant-source]").forEach((card) => {
      const enable = card.querySelector("[data-grant-enabled]");
      if (enable) enable.disabled = !custom;
      if (custom && !enable.checked) {
        enable.checked = true;
        card.querySelectorAll("[data-grant-column]").forEach((input) => { input.checked = true; });
      }
      syncGrantCard(card);
    });
  }
}

function handleAdminModalClick(event) {
  if (event.target.matches("[data-admin-backdrop]")) return closeAdminModal();
  if (event.target.closest('[data-admin-action="close-modal"]')) closeAdminModal();
}

async function handleAdminModalSubmit(event) {
  const form = event.target.closest("[data-modal-form]");
  if (!form) return;
  event.preventDefault();
  const kind = form.dataset.modalForm;
  if (kind === "scope-locked") return closeAdminModal();
  const submit = form.querySelector('button[type="submit"]');
  const errorNode = form.querySelector(".modal-error");
  const showError = (message) => { errorNode.textContent = message; errorNode.classList.remove("hidden"); };
  errorNode.classList.add("hidden");
  if (submit) { submit.disabled = true; submit.textContent = "Saving…"; }
  try {
    let url, method, body;
    const fields = new FormData(form);
    if (kind === "user-create" || kind === "user-edit") {
      body = {
        username: String(fields.get("username") || "").trim(), fullName: String(fields.get("fullName") || "").trim(),
        roleId: Number(fields.get("roleId")), deptId: fields.get("deptId") || null,
        region: String(fields.get("region") || "").trim() || null, isActive: fields.get("isActive") === "true",
      };
      const password = String(fields.get("password") || "");
      if (password) body.password = password;
      url = kind === "user-create" ? "/admin/users" : "/admin/users/" + encodeURIComponent(form.dataset.userId);
      method = kind === "user-create" ? "POST" : "PATCH";
    } else if (kind === "role-create" || kind === "role-edit") {
      body = {name: String(fields.get("name") || "").trim(), description: String(fields.get("description") || "").trim(), sources: gatherGrantList(form)};
      url = kind === "role-create" ? "/admin/roles" : "/admin/roles/" + encodeURIComponent(selectedRoleId);
      method = kind === "role-create" ? "POST" : "PATCH";
    } else if (kind === "user-scope") {
      const mode = $("userScopeMode")?.value || "inherit";
      body = {mode, sources: mode === "custom" ? gatherGrantList(form) : []};
      url = "/admin/users/" + encodeURIComponent(userScopePayload.userId || form.dataset.userId) + "/data-access";
      if (!form.dataset.userId) {
        const match = (adminUsersPayload.users || []).find((item) => item.FullName + " · " + item.Role === form.querySelector(".grant-mode-control strong")?.textContent);
        if (!match) throw new Error("The user selection expired. Reload the directory and try again.");
        url = "/admin/users/" + encodeURIComponent(match.UserID) + "/data-access";
      }
      method = "PUT";
    } else return;
    const response = await apiFetch(url, {method, headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
    const result = await readJsonResponse(response, "The change could not be saved");
    if (!response.ok) throw new Error(result.error || "The change could not be saved.");
    closeAdminModal();
    showToast(result.sessionsRevoked ? "Saved. Existing sessions were signed out." : "Changes saved.");
    if (currentView === "directory") await loadDirectory(adminDirectoryTab);
  } catch (error) {
    if (error.name !== "AbortError") showError(error.message);
  } finally {
    if (submit && submit.isConnected) { submit.disabled = false; submit.textContent = kind.includes("create") ? (kind.startsWith("user") ? "Create account" : "Create role") : (kind === "user-scope" ? "Save access" : kind === "user-edit" ? "Save account" : "Save role"); }
  }
}

async function handleAdminAction(button) {
  const action = button.dataset.adminAction;
  if (action === "close-modal") return closeAdminModal();
  if (action === "open-users") return loadDirectory("users");
  if (action === "open-roles" || action === "directory-roles") return loadDirectory("roles");
  if (action === "directory-users") return loadDirectory("users");
  if (action === "open-database-map") return loadDatabaseMap();
  if (action === "open-audit") return loadAudit();
  if (action === "refresh-directory") return loadDirectory(adminDirectoryTab);
  if (action === "new-user") return openUserModal();
  if (action === "edit-user") {
    const item = (adminUsersPayload.users || []).find((record) => String(record.UserID) === button.dataset.userId);
    const form = openUserModal(button.dataset.userId);
    const shell = $("modalRoot").querySelector("[data-modal-form]");
    if (shell && item) shell.dataset.userId = item.UserID;
    return form;
  }
  if (action === "user-scope") {
    const id = button.dataset.userId;
    await openUserScopeModal(id);
    const form = $("modalRoot").querySelector('[data-modal-form="user-scope"]');
    if (form) form.dataset.userId = id;
    return;
  }
  if (action === "new-role") return openRoleModal();
  if (action === "edit-role") return openRoleModal(button.dataset.roleId);
  if (action === "schema-node") return showSchemaDetail(button.dataset.sourceName);
}
