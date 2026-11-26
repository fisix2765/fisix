const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];

// ===== Cuentas locales de prueba (sin servidor ni Firebase) =====
// Solo separa perfiles dentro de este navegador. No es autenticación segura
// para publicar y no sincroniza entre dispositivos.
const FISIX_USERS_KEY = "fisix_local_users_v1";
const FISIX_SESSION_KEY = "fisix_local_session_v1";
const FISIX_PBKDF2_ITERATIONS = 210000;
let authMode = "login";

function readLocalUsers() {
  try {
    const value = JSON.parse(localStorage.getItem(FISIX_USERS_KEY) || "{}");
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  } catch { return {}; }
}

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach(byte => binary += String.fromCharCode(byte));
  return btoa(binary);
}

async function hashLocalPassword(password, saltBase64) {
  if (!window.crypto?.subtle) {
    throw new Error("El navegador necesita HTTPS o localhost para proteger la contraseña.");
  }
  const salt = saltBase64
    ? Uint8Array.from(atob(saltBase64), char => char.charCodeAt(0))
    : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2", salt, iterations: FISIX_PBKDF2_ITERATIONS, hash: "SHA-256"
  }, keyMaterial, 256);
  return { salt: bytesToBase64(salt), hash: bytesToBase64(new Uint8Array(bits)) };
}

function setAuthMode(mode) {
  authMode = mode;
  const registering = mode === "register";
  $("#authTitle").textContent = registering ? "Crea tu cuenta" : "Bienvenido a Fisix";
  $("#authDescription").textContent = registering
    ? "Regístrate para crear tu espacio de aprendizaje."
    : "Inicia sesión para acceder a tus herramientas y conversaciones.";
  $("#authSubmit").textContent = registering ? "Crear cuenta" : "Iniciar sesión";
  $("#authPassword").autocomplete = registering ? "new-password" : "current-password";
  $("#authSwitchText").textContent = registering ? "¿Ya tienes una cuenta?" : "¿Todavía no tienes una cuenta?";
  $("#authSwitch").textContent = registering ? "Iniciar sesión" : "Crear cuenta";
  $("#authFeedback").textContent = "";
}

function updateAccountUI() {
  const username = currentFisixUser || "Estudiante";
  $("#accountName").textContent = username;
  $("#accountAvatar").textContent = username.slice(0, 1).toUpperCase();
}

function showFisixApp(username) {
  if (typeof closeAccountMenu === "function") closeAccountMenu();
  currentFisixUser = username;
  localStorage.setItem(FISIX_SESSION_KEY, username);
  savedChatRecords = loadSavedChats();
  activeChat = null;
  chatHistory = [];
  $("#messages").innerHTML = "";
  $("#welcomeChat").style.display = "block";
  $("#appShell").hidden = false;
  $("#authScreen").hidden = true;
  updateAccountUI();
  renderSavedChats();
}

function logoutFisix() {
  if (activeChat?.messages?.length) saveActiveChat();
  ++chatRequestId;
  if (currentChatController) currentChatController.abort();
  currentChatController = null;
  if (typeof setChatBusy === "function") setChatBusy(false);
  currentFisixUser = null;
  activeChat = null;
  chatHistory = [];
  savedChatRecords = [];
  localStorage.removeItem(FISIX_SESSION_KEY);
  $("#appShell").hidden = true;
  $("#authScreen").hidden = false;
  $("#authPassword").value = "";
  $("#authUsername").value = "";
  setAuthMode("login");
}

$("#authSwitch").addEventListener("click", () => {
  setAuthMode(authMode === "login" ? "register" : "login");
});

$("#authForm").addEventListener("submit", async event => {
  event.preventDefault();
  const username = $("#authUsername").value.trim().toLowerCase();
  const password = $("#authPassword").value;
  const feedback = $("#authFeedback");
  const submit = $("#authSubmit");
  feedback.textContent = "";
  if (!/^[a-z0-9_-]{3,20}$/.test(username)) {
    feedback.textContent = "Usa entre 3 y 20 caracteres: letras sin tilde, números, guion o guion bajo.";
    return;
  }
  if (password.length < 8) {
    feedback.textContent = "La contraseña debe tener al menos 8 caracteres.";
    return;
  }
  submit.disabled = true;
  submit.textContent = authMode === "register" ? "Creando cuenta…" : "Verificando…";
  try {
    const users = readLocalUsers();
    if (authMode === "register") {
      if (users[username]) {
        feedback.textContent = "Ese nombre de usuario ya está registrado en este navegador.";
        return;
      }
      const credentials = await hashLocalPassword(password);
      users[username] = { salt: credentials.salt, passwordHash: credentials.hash, createdAt: Date.now() };
      localStorage.setItem(FISIX_USERS_KEY, JSON.stringify(users));

      // Migra el historial anterior a la primera cuenta creada para conservarlo.
      const legacy = localStorage.getItem(FISIX_CHATS_KEY);
      const accountKey = `${FISIX_CHATS_KEY}_${username}`;
      if (legacy && !localStorage.getItem(accountKey)) {
        localStorage.setItem(accountKey, legacy);
        localStorage.removeItem(FISIX_CHATS_KEY);
      }
      showFisixApp(username);
    } else {
      const user = users[username];
      if (!user) {
        feedback.textContent = "No encontramos esa cuenta en este navegador. Comprueba el usuario o crea una cuenta.";
        return;
      }
      const credentials = await hashLocalPassword(password, user.salt);
      if (credentials.hash !== user.passwordHash) {
        feedback.textContent = "La contraseña es incorrecta.";
        return;
      }
      showFisixApp(username);
    }
  } catch (error) {
    feedback.textContent = error?.name === "QuotaExceededError"
      ? "No hay espacio suficiente en el almacenamiento del navegador."
      : (error.message || "No se pudo completar la operación.");
  } finally {
    submit.disabled = false;
    submit.textContent = authMode === "register" ? "Crear cuenta" : "Iniciar sesión";
  }
});

const accountMenuTrigger = $("#accountMenuTrigger");
const accountMenu = $("#accountMenu");

function closeAccountMenu() {
  accountMenu.hidden = true;
  accountMenuTrigger.setAttribute("aria-expanded", "false");
}

accountMenuTrigger.addEventListener("click", event => {
  event.stopPropagation();
  accountMenu.hidden = !accountMenu.hidden;
  accountMenuTrigger.setAttribute("aria-expanded", String(!accountMenu.hidden));
});

document.addEventListener("click", event => {
  if (!event.target.closest(".account-menu-wrap")) closeAccountMenu();
});

document.addEventListener("keydown", event => {
  if (event.key === "Escape") closeAccountMenu();
});

// Cambiar de cuenta y cerrar sesión vuelven a la pantalla de acceso.
// La diferencia es el nombre de la acción que el usuario eligió.
$("#switchAccountButton").addEventListener("click", () => {
  closeAccountMenu();
  logoutFisix();
  $("#authFeedback").textContent = "Puedes iniciar sesión con otra cuenta o crear una nueva.";
});

$("#logoutButton").addEventListener("click", () => {
  closeAccountMenu();
  logoutFisix();
});




// ===== Idioma global de Fisix (ES / EN) =====
const FISIX_TRANSLATIONS = {
  "Inicio":"Home","Asistente IA":"AI Assistant","Simuladores":"Simulators","Cuestionarios":"Quizzes",
  "Fórmulas":"Formulas","Calculadora":"Calculator","Conversor de unidades":"Unit converter",
  "Nuevo chat":"New chat","MENÚ PRINCIPAL":"MAIN MENU","CHATS GUARDADOS":"SAVED CHATS","CHATS RECIENTES":"RECENT CHATS",
  "Tus chats se guardarán aquí cuando comiences una conversación.":"Your chats will appear here when you start a conversation.",
  "Estudiante":"Student","Espacio de aprendizaje":"Learning space","Idioma":"Language",
  "Seleccionar idioma":"Select language","Español":"Spanish","Explorar asistente":"Explore assistant",
  "TU ESPACIO DE APRENDIZAJE":"YOUR LEARNING SPACE","La física, más fácil":"Physics, made easier",
  "entender.":"to understand.","Aprende, experimenta y resuelve problemas de física con herramientas diseñadas para ti.":"Learn, experiment, and solve physics problems with tools designed for you.",
  "HERRAMIENTAS":"TOOLS","¿Qué quieres aprender hoy?":"What would you like to learn today?",
  "Todo lo que necesitas en un solo lugar":"Everything you need in one place",
  "Resuelve tus dudas y estudia con tus propios documentos.":"Get answers to your questions and study with your own documents.",
  "Comenzar chat":"Start chatting","Experimenta con conceptos de física de forma interactiva.":"Experiment with physics concepts interactively.",
  "Ver simuladores":"View simulators","Pon a prueba lo que sabes y revisa tus resultados.":"Test your knowledge and review your results.",
  "Practicar ahora":"Practice now","Consulta las ecuaciones más importantes de cada tema.":"Explore the most important equations for each topic.",
  "Ver fórmulas":"View formulas","Realiza operaciones y calcula variables de física.":"Perform calculations and solve for physics variables.",
  "Abrir calculadora":"Open calculator","Cambia entre unidades de medida al instante.":"Convert between measurement units instantly.",
  "Convertir unidades":"Convert units","Un paso a la vez. Entender es mejor que memorizar.":"One step at a time. Understanding is better than memorizing.",
  "TU COMPAÑERO DE ESTUDIO":"YOUR STUDY COMPANION","Pregunta, aprende y explora conceptos de física.":"Ask questions, learn, and explore physics concepts.",
  "¡Hola! ¿Qué vamos a aprender hoy?":"Hello! What shall we learn today?",
  "Puedo ayudarte a comprender conceptos, resolver ejercicios paso a paso o estudiar con tus fuentes.":"I can help you understand concepts, solve problems step by step, or study using your sources.",
  "⚡ Entender un tema":"⚡ Understand a topic","Explícame la ley de Ohm desde cero":"Explain Ohm's law from scratch",
  "∑ Resolver un ejercicio":"∑ Solve a problem","Ayúdame con un ejercicio de Faraday":"Help me with a Faraday problem",
  "▤ Repasar para un examen":"▤ Review for an exam","Resume reflexión y espejos":"Summarize reflection and mirrors",
  "◉ Aclarar una duda":"◉ Clarify a question","¿Qué significa el campo magnético?":"What does magnetic field mean?",
  "Escribe tu pregunta...":"Type your question...","Adjuntar archivo":"Attach file","Enviar":"Send",
  "Fisix es una demostración. Sus respuestas son simuladas y pueden contener errores.":"Fisix is a demo. Its answers are simulated and may contain errors.",
  "CONTEXTO DE ESTUDIO":"STUDY CONTEXT","Mis fuentes":"My sources",
  "Agrega tus materiales para tenerlos organizados en este espacio.":"Add your materials to keep them organized here.",
  "Subir documentos":"Upload documents","Seleccionar archivos":"Choose files","ARCHIVOS AGREGADOS":"ADDED FILES",
  "Aún no has agregado fuentes.":"You haven't added any sources yet.",
  "En esta versión puedes cargar y organizar archivos. La lectura y consulta inteligente de su contenido se integrará junto con la IA.":"In this version, you can upload and organize files. Reading and intelligently querying their contents will be integrated with the AI.",
  "Quitar archivo":"Remove file","Formato no admitido: ":"Unsupported format: ",
  "APRENDE EXPERIMENTANDO":"LEARN BY EXPERIMENTING","Modifica los valores y observa cómo cambian los resultados.":"Change the values and see how the results change.",
  "Ley de Ohm":"Ohm's law","Campo magnético":"Electromagnetic field","Ley de Faraday":"Faraday's law",
  "Reflexión y espejos":"Reflection and mirrors","Voltaje (V)":"Voltage (V)","Resistencia (Ω)":"Resistance (Ω)",
  "Carga (µC)":"Charge (µC)","Velocidad (m/s)":"Speed (m/s)","Campo magnético (T)":"Magnetic field (T)",
  "Ángulo (°)":"Angle (°)","Número de espiras (N)":"Number of turns (N)","Cambio de flujo (Wb)":"Change in flux (Wb)",
  "Intervalo de tiempo (s)":"Time interval (s)","Ángulo de incidencia (°)":"Angle of incidence (°)",
  "Distancia del objeto al espejo (cm)":"Object distance from mirror (cm)",
  "Explora la relación entre voltaje, corriente y resistencia en un circuito eléctrico.":"Explore the relationship between voltage, current, and resistance in an electrical circuit.",
  "Observa cómo cambia la fuerza magnética sobre una carga en movimiento.":"See how the magnetic force on a moving charge changes.",
  "Modifica el número de espiras y la variación del flujo magnético para calcular la FEM inducida.":"Change the number of turns and the magnetic flux variation to calculate the induced EMF.",
  "Cambia el ángulo de incidencia y observa el ángulo de reflexión en un espejo plano.":"Change the angle of incidence and observe the angle of reflection in a plane mirror.",
  "Electricidad":"Electricity","Electromagnetismo":"Electromagnetism","Inducción magnética":"Magnetic induction","Óptica":"Optics",
  "amperios (A)":"amperes (A)","newtons (N)":"newtons (N)","voltios (V)":"volts (V)","grados (ángulo de reflexión)":"degrees (angle of reflection)",
  "Al aplicar ":"When "," V a una resistencia de ":" V is applied to a resistance of "," Ω, la corriente resultante es ":" Ω, the resulting current is ",".":".",
  "F = |q| · v · B · sen(θ). Se muestra la magnitud de la fuerza magnética; la dirección depende de los sentidos de v y B.":"F = |q| · v · B · sin(θ). The magnitude of the magnetic force is shown; its direction depends on the directions of v and B.",
  "ε = −N · ΔΦ / Δt. El signo negativo expresa la ley de Lenz; el resultado conserva ese signo.":"ε = −N · ΔΦ / Δt. The negative sign represents Lenz's law; the result retains that sign.",
  "θᵣ = θᵢ. Para un espejo plano, la imagen se forma a ":"θᵣ = θᵢ. For a plane mirror, the image forms "," cm detrás del espejo y tiene el mismo tamaño que el objeto.":" cm behind the mirror and is the same size as the object.",
  "RESULTADO DEL SIMULADOR":"SIMULATOR RESULT","Al aplicar ":"When "," a una resistencia de ":" is applied to a resistance of ",
  "PON A PRUEBA TUS CONOCIMIENTOS":"TEST YOUR KNOWLEDGE","Practica con preguntas de los 16 temas del nuevo temario.":"Practice questions from all 16 syllabus topics.",
  "Aprende de tus errores":"Learn from your mistakes","Al finalizar podrás revisar las respuestas correctas y comprender por qué.":"At the end, you can review the correct answers and understand why.",
  "preguntas disponibles":"questions available","temas de física":"physics topics",
  "RESUMEN DE ECUACIONES":"EQUATION SUMMARY","Consulta las ecuaciones y envíalas directamente a la calculadora.":"Explore equations and send them directly to the calculator.",
  "Todas":"All","Óptica":"Optics","Relaciona voltaje, corriente y resistencia.":"Relates voltage, current, and resistance.",
  "Fuerza magnética":"Magnetic force","Fuerza magnética sobre una carga en movimiento.":"Magnetic force on a moving charge.",
  "Fuerza electromotriz inducida por variación del flujo.":"Electromotive force induced by a change in magnetic flux.",
  "El ángulo de incidencia es igual al de reflexión.":"The angle of incidence equals the angle of reflection.",
  "La distancia de la imagen es igual a la del objeto.":"The image distance equals the object distance.",
  "Usar en la calculadora →":"Use in calculator →","Deja vacío para calcular":"Leave blank to calculate",
  "Ingresa ":"Enter ","Completa los datos y presiona calcular.":"Enter the values and press calculate.",
  "En la ley de Ohm deja vacía exactamente la variable que deseas calcular.":"For Ohm's law, leave exactly the variable you want to calculate blank.",
  "Revisa los valores ingresados.":"Check the values you entered.","Completa todos los campos.":"Complete all fields.",
  "No se puede calcular con esos valores.":"These values cannot be used for this calculation.",
  "Resultado calculado a partir de la fórmula seleccionada.":"Result calculated using the selected formula.",
  "RESUELVE Y COMPRUEBA":"CALCULATE AND CHECK","Realiza operaciones o selecciona una fórmula para calcular una variable.":"Perform operations or select a formula to solve for a variable.",
  "OPERACIÓN":"OPERATION","CALCULADORA DE FÍSICA":"PHYSICS CALCULATOR","Usar una fórmula":"Use a formula",
  "Selecciona una ecuación e ingresa los datos conocidos.":"Select an equation and enter the known values.",
  "Fórmula":"Formula","Calcular resultado":"Calculate result","RESULTADO":"RESULT",
  "CONVERSIONES RÁPIDAS":"QUICK CONVERSIONS","Convierte magnitudes físicas comunes de manera sencilla.":"Easily convert common physical quantities.",
  "Magnitud":"Quantity","Longitud":"Length","Masa":"Mass","Tiempo":"Time","Velocidad":"Speed","Fuerza":"Force",
  "Energía":"Energy","Carga eléctrica":"Electric charge","Voltaje":"Voltage","De":"From",
  "Unidad inicial":"From unit","Unidad final":"To unit","RESULTADO DE LA CONVERSIÓN":"CONVERSION RESULT",
  "Pregunta ":"Question "," de ":" of ","% completado":"% complete","RESULTADO FINAL":"FINAL RESULT",
  "¡Correcto!":"Correct!","Respuesta incorrecta.":"Incorrect answer.","← Anterior":"← Previous",
  "Siguiente →":"Next →","Finalizar cuestionario":"Finish quiz","Ver resultado":"View result",
  "Selecciona una respuesta.":"Select an answer.","Responde todas las preguntas antes de finalizar.":"Answer all questions before finishing.",
  "Revisar respuestas":"Review answers","Volver a intentar":"Try again",
  "Has respondido correctamente ":"You answered "," de ":" out of "," preguntas.":" questions correctly.",
  "Consulta cancelada.":"Request cancelled.","Pensando…":"Thinking…",
  "Consultando a Gemini…":"Thinking…",
  "No se pudo obtener una respuesta.":"Could not get a response.",
  "No se ingresó una API key.":"No API key was entered.","Clave de Gemini configurada para esta pestaña.":"Gemini key configured for this tab.",
  "Debes configurar tu API key para consultar Gemini.":"You must configure your API key to use Gemini.",
  "No se pudo conectar a Gemini. Verifica tu conexión. Si aparece un error de CORS, puede ser necesario revisar las restricciones de acceso desde el navegador.":"Could not connect to Gemini. Check your connection. If you see a CORS error, browser access restrictions may need to be reviewed.",
  "Solicitud incorrecta. Revisa los datos enviados.":"Invalid request. Check the submitted data.",
  "La API rechazó la clave o no tiene permiso para usar Gemini. Vuelve a enviar tu pregunta para introducir una clave válida.":"The API rejected the key or it does not have permission to use Gemini. Click “⚙ Gemini” to configure it again.",
  "El modelo ":"The model "," no está disponible para esta clave.":" is not available for this key.",
  "Límite de solicitudes de Gemini alcanzado. Inténtalo más tarde.":"Gemini request limit reached. Try again later.",
  "Gemini está saturado temporalmente (HTTP 503). Vuelve a intentarlo.":"Gemini is temporarily overloaded (HTTP 503). Try again.",
  "Este navegador no permite recibir la respuesta por fragmentos.":"This browser cannot receive the response in streaming chunks.",
  "Se recibió un fragmento inválido de Gemini.":"An invalid Gemini response chunk was received.",
  "Error en el stream de Gemini.":"Error in the Gemini stream.",
  "Gemini no devolvió texto; la solicitud puede haber sido bloqueada.":"Gemini returned no text; the request may have been blocked.",
  "Espera a que Gemini termine de responder.":"Wait for Gemini to finish responding.",
  "El historial persistente aún no está habilitado.":"Persistent chat history is not enabled yet.",
  "No hay texto para copiar.":"There is no text to copy.","Traducción copiada.":"Text copied.","No se pudo copiar automáticamente.":"Could not copy automatically.",
  "Escribe un texto para traducir.":"Enter text to translate.","Divide el texto en fragmentos de menos de 4500 caracteres.":"Split the text into chunks of fewer than 4,500 characters.",
  "No se pudo traducir. Comprueba tu conexión e inténtalo de nuevo.":"Translation failed. Check your connection and try again.",
  "No se pudo conectar":"Could not connect","Traducción completada":"Translation complete",
  "La interfaz está disponible en español. El traductor permite español e inglés.":"The interface is available in Spanish and English.",
  "Explícame la ley de Ohm desde cero.":"Explain Ohm's law from scratch.",
  "Ayúdame a resolver un ejercicio de la ley de Faraday.":"Help me solve a Faraday's law problem.",
  "Hazme un resumen de reflexión y espejos.":"Summarize reflection and mirrors.",
  "¿Qué significa el campo magnético?":"What does magnetic field mean?",
  "Fisix":"Fisix","Conversor":"Converter","＋ Nuevo chat":"＋ New chat","Aprende a tu ritmo":"Learn at your own pace","Abrir menú":"Open menu","Cerrar menú":"Close menu",
  "LEY DE OHM":"OHM'S LAW","CAMPO MAGNÉTICO":"MAGNETIC FIELD","LEY DE FARADAY":"FARADAY'S LAW","REFLEXIÓN Y ESPEJOS":"REFLECTION AND MIRRORS",
  "¿Qué establece la ley de Ohm?":"What does Ohm's law state?",
  "La relación entre voltaje, corriente y resistencia":"The relationship between voltage, current, and resistance",
  "La relación entre masa y aceleración":"The relationship between mass and acceleration",
  "La reflexión de la luz":"The reflection of light",
  "Una resistencia de 6 Ω se conecta a 12 V. ¿Qué corriente circula?":"A 6 Ω resistor is connected to 12 V. What current flows?",
  "0,5 A":"0.5 A","2 A":"2 A","72 A":"72 A",
  "Si el voltaje se mantiene constante y la resistencia aumenta, la corriente…":"If voltage remains constant and resistance increases, the current…",
  "Aumenta":"Increases","Disminuye":"Decreases","No cambia":"Does not change",
  "¿Qué condición permite que una carga experimente fuerza magnética?":"What condition allows a charge to experience a magnetic force?",
  "Estar en movimiento dentro de un campo magnético":"Moving within a magnetic field",
  "Estar siempre en reposo":"Always being at rest","Tener masa igual a cero":"Having zero mass",
  "¿En qué unidad se mide el campo magnético B en el SI?":"What is the SI unit of magnetic field B?",
  "Voltio":"Volt","Tesla":"Tesla","Ohmio":"Ohm",
  "¿Qué ocurre con la fuerza magnética si la velocidad es paralela al campo B?":"What happens to the magnetic force if velocity is parallel to field B?",
  "Es máxima":"It is maximum","Es cero":"It is zero","Se duplica":"It doubles",
  "¿Qué fenómeno describe la ley de Faraday?":"What phenomenon does Faraday's law describe?",
  "La inducción electromagnética":"Electromagnetic induction","La caída libre":"Free fall",
  "Si aumenta el número de espiras y todo lo demás permanece constante, la FEM inducida en magnitud…":"If the number of turns increases and everything else remains constant, the induced EMF magnitude…",
  "La FEM inducida por un cambio en el flujo magnético.":"The EMF induced by a change in magnetic flux.",
  "¿Qué representa el signo negativo en la ley de Faraday-Lenz?":"What does the negative sign in Faraday-Lenz's law represent?",
  "La conservación de la masa":"Conservation of mass","La oposición al cambio de flujo":"Opposition to the change in flux",
  "Que el voltaje siempre es negativo":"That voltage is always negative",
  "¿Qué relación existe entre el ángulo de incidencia y el de reflexión?":"What is the relationship between the angle of incidence and the angle of reflection?",
  "Son iguales":"They are equal","Uno es el doble del otro":"One is twice the other","Siempre suman 90°":"They always add up to 90°",
  "¿Cómo es la imagen que forma un espejo plano?":"What is the image formed by a plane mirror like?",
  "Real e invertida":"Real and inverted","Virtual, derecha y del mismo tamaño":"Virtual, upright, and the same size","Real y aumentada":"Real and magnified",
  "Un objeto está a 20 cm de un espejo plano. ¿A qué distancia detrás del espejo aparece la imagen?":"An object is 20 cm from a plane mirror. How far behind the mirror does its image appear?",
  "10 cm":"10 cm","20 cm":"20 cm","40 cm":"40 cm",
  "La ley de Ohm establece que el voltaje es igual al producto de la corriente por la resistencia: V = I · R.":"Ohm's law states that voltage equals current multiplied by resistance: V = I · R.",
  "I = V/R = 12/6 = 2 A.":"I = V/R = 12/6 = 2 A.",
  "Por I = V/R, corriente y resistencia son inversamente proporcionales cuando el voltaje es constante.":"From I = V/R, current and resistance are inversely proportional when voltage is constant.",
  "La fuerza magnética sobre una carga depende de su velocidad y del campo magnético.":"The magnetic force on a charge depends on its velocity and the magnetic field.",
  "La unidad del campo magnético en el SI es el tesla (T).":"The SI unit of magnetic field is the tesla (T).",
  "F = |q|vB sen θ. Si θ = 0°, sen 0° = 0 y la fuerza magnética es nula.":"F = |q|vB sin θ. If θ = 0°, sin 0° = 0, so the magnetic force is zero.",
  "La ley de Faraday describe la FEM inducida por un cambio en el flujo magnético.":"Faraday's law describes the EMF induced by a change in magnetic flux.",
  "La magnitud de la FEM es proporcional al número de espiras: |ε| = N|ΔΦ/Δt|.":"The EMF magnitude is proportional to the number of turns: |ε| = N|ΔΦ/Δt|.",
  "El signo negativo expresa la ley de Lenz: la corriente inducida se opone al cambio de flujo que la produce.":"The negative sign expresses Lenz's law: the induced current opposes the change in flux that produces it.",
  "La ley de reflexión establece que θᵢ = θᵣ, medidos respecto a la normal.":"The law of reflection states that θᵢ = θᵣ, measured from the normal.",
  "Un espejo plano forma una imagen virtual, derecha y de igual tamaño que el objeto.":"A plane mirror forms a virtual, upright image that is the same size as the object.",
  "En un espejo plano, la distancia imagen es igual a la distancia objeto.":"In a plane mirror, the image distance equals the object distance.",
  "Fuente de voltaje  ───── Resistencia":"Voltage source  ───── Resistor",
  "q  → v      × B":"q  → v      × B","Bobina  )))))   ↗ Flujo magnético":"Coil  )))))   ↗ Magnetic flux",
  "Selecciona una respuesta.":"Select an answer.","No hay texto para copiar.":"There is no text to copy.",
  "Language changed to English.":"Language changed to English.","Idioma cambiado a español.":"Language changed to Spanish.",
  "Asistente":"Assistant","Ayúdame con un ejercicio de Faraday":"Help me with a Faraday problem",
  "Resume reflexión y espejos":"Summarize reflection and mirrors","Faraday":"Faraday's law",
  "Ley de reflexión":"Law of reflection","Espejo plano":"Plane mirror","No cambia":"Does not change",
  "La física, más fácil":"Physics, made easier","PDF, DOC, DOCX, PPT, PPTX, TXT":"PDF, DOC, DOCX, PPT, PPTX, TXT",
  "Tu espacio de aprendizaje":"Your learning space","Resultado calculado a partir de la fórmula seleccionada.":"Result calculated using the selected formula.",
  "Fórmula —":"Formula —","El resultado conserva ese signo.":"The result retains that sign.",
  "En esta versión puedes cargar y organizar archivos.":"In this version, you can upload and organize files.",
  "Pregunta":"Question","El modelo ":"The model ",
  "Es máxima":"It is maximum","Se vuelve cero":"It becomes zero","La conservación de la masa":"Conservation of mass",
  "Que el voltaje siempre es negativo":"That voltage is always negative",
  "La distancia de la imagen es igual a la del objeto.":"The image distance equals the object distance.",
  "No se pudo conectar a Gemini.":"Could not connect to Gemini.",
  "Error de Gemini (HTTP ":"Gemini error (HTTP ",
  "Revisa los valores ingresados.":"Check the values you entered.",
  "Aprende física":"Learn physics","Fisix | Aprende física":"Fisix | Learn physics",
  "Electricidad":"Electricity","Circuitos":"Circuits","Magnetismo":"Magnetism","Ondas":"Waves","Mecánica":"Mechanics","Térmica":"Thermal physics","Óptica":"Optics",
  "Ley de Coulomb":"Coulomb's law","Campo eléctrico":"Electric field","Ley de Gauss":"Gauss's law","Potencial eléctrico":"Electric potential","Campo magnético":"Magnetic field","Ley de Ampère":"Ampere's law","Circuito en serie":"Series circuit","Ondas electromagnéticas":"Electromagnetic waves","Caída libre":"Free fall","Tiro parabólico":"Projectile motion","MRU":"Uniform motion (MRU)","MRUV":"Uniformly accelerated motion (MRUV)","Trabajo mecánico":"Mechanical work","Energía cinética":"Kinetic energy","Dilatación lineal":"Linear expansion","Calorimetría":"Calorimetry",
  "Fuerza eléctrica entre dos cargas puntuales.":"Electric force between two point charges.","Campo creado por una carga puntual.":"Electric field created by a point charge.","Flujo eléctrico a través de una superficie cerrada.":"Electric flux through a closed surface.","Potencial debido a una carga puntual.":"Potential due to a point charge.","Voltaje a partir de corriente y resistencia.":"Voltage from current and resistance.","Fuerza magnética sobre una carga en movimiento.":"Magnetic force on a moving charge.","Campo magnético alrededor de un conductor rectilíneo largo.":"Magnetic field around a long straight conductor.","FEM inducida por variación del flujo magnético.":"EMF induced by a change in magnetic flux.","Resistencia equivalente de tres resistencias en serie.":"Equivalent resistance of three resistors in series.","Relación entre longitud de onda y frecuencia en el vacío.":"Relationship between wavelength and frequency in vacuum.","El ángulo de incidencia es igual al de reflexión.":"The angle of incidence equals the angle of reflection.","La imagen se forma a la misma distancia detrás del espejo.":"The image forms the same distance behind the mirror.","Velocidad tras caer durante un tiempo t, sin resistencia del aire.":"Speed after falling for time t, neglecting air resistance.","Alcance horizontal cuando el proyectil aterriza a la altura de lanzamiento.":"Horizontal range when the projectile lands at its launch height.","Desplazamiento en movimiento rectilíneo uniforme.":"Displacement in uniform straight-line motion.","Velocidad final con aceleración constante.":"Final velocity with constant acceleration.","Trabajo realizado por una fuerza constante.":"Work done by a constant force.","Energía asociada al movimiento de un cuerpo.":"Energy associated with an object's motion.","Cambio de longitud por variación de temperatura.":"Change in length due to a temperature change.","Calor sensible absorbido o cedido por una sustancia.":"Sensible heat absorbed or released by a substance."
};

let fisixLanguage = (() => {
  try { return localStorage.getItem("fisix-language") === "en" ? "en" : "es"; }
  catch { return "es"; }
})();
const fisixOriginalText = new WeakMap();
const fisixOriginalAttrs = new WeakMap();
let fisixApplyingTranslations = false;

function translateFisixText(value) {
  if (fisixLanguage !== "en" || !value) return value;
  const trimmed = value.trim();
  if (!trimmed) return value;
  let translated = FISIX_TRANSLATIONS[trimmed];
  if (!translated) {
    translated = trimmed
      .replace(/^Pregunta (\d+) de (\d+)$/, "Question $1 of $2")
      .replace(/^(.+) — (V = I · R|F = \|q\| · v · B · sen θ|ε = −N · ΔΦ \/ Δt|θᵢ = θᵣ|dᵢ = dₒ)$/, (m, title, equation) => ({ "Ley de Ohm":"Ohm's law", "Fuerza magnética":"Magnetic force", "Ley de Faraday":"Faraday's law", "Ley de reflexión":"Law of reflection", "Espejo plano":"Plane mirror" }[title] || title) + " — " + equation.replace("sen θ", "sin θ"))
      .replace(/^(\d+)% completado$/, "$1% complete")
      .replace(/^(\d+) caracteres$/, "$1 characters")
      .replace(/^Formato no admitido: (.+)$/, "Unsupported format: $1")
      .replace(/^El modelo (.+) no está disponible para esta clave\.$/, "The model $1 is not available for this key.")
      .replace(/^No se pudo obtener una respuesta\.\n?/, "Could not get a response.\n")
      .replace(/^Has respondido correctamente (\d+) de (\d+) preguntas\.$/, "You answered $1 out of $2 questions correctly.")
      .replace(/^Al aplicar (.+) V a una resistencia de (.+) Ω, la corriente resultante es (.+) \/ (.+)\.$/, "When $1 V is applied to a resistance of $2 Ω, the resulting current is $3 / $4.")
      .replace(/^Para un espejo plano, la imagen se forma a (.+) cm detrás del espejo y tiene el mismo tamaño que el objeto\.$/, "For a plane mirror, the image forms $1 cm behind the mirror and is the same size as the object.")
      .replace(/^θᵣ = θᵢ\. Para un espejo plano, la imagen se forma a (.+) cm detrás del espejo y tiene el mismo tamaño que el objeto\.$/, "θᵣ = θᵢ. For a plane mirror, the image forms $1 cm behind the mirror and is the same size as the object.");
  }
  if (translated === trimmed) return value;
  const leading = value.match(/^\s*/)?.[0] || "";
  const trailing = value.match(/\s*$/)?.[0] || "";
  return leading + translated + trailing;
}

function translateFisixNode(node) {
  if (node.nodeType === Node.TEXT_NODE) {
    if (!fisixOriginalText.has(node)) fisixOriginalText.set(node, node.data);
    const original = fisixOriginalText.get(node);
    let next = translateFisixText(original);
    if (fisixLanguage === "en" && node.parentElement?.closest(".hero h1") && original.trim() === "de") {
      next = original.replace("de", "to");
    }
    if (fisixLanguage === "en" && original.trim() === "A" && node.parentElement?.closest(".conversion-row")) {
      next = original.replace("A", "To");
    }
    if (node.data !== next) node.data = next;
    return;
  }
  if (node.nodeType !== Node.ELEMENT_NODE) return;
  const attrs = ["placeholder", "title", "aria-label", "data-prompt"];
  let originals = fisixOriginalAttrs.get(node);
  if (!originals) { originals = {}; fisixOriginalAttrs.set(node, originals); }
  for (const attr of attrs) {
    if (node.hasAttribute(attr)) {
      if (!(attr in originals)) originals[attr] = node.getAttribute(attr);
      const next = translateFisixText(originals[attr]);
      if (node.getAttribute(attr) !== next) node.setAttribute(attr, next);
    }
  }
  for (const child of node.childNodes) translateFisixNode(child);
}

function applyFisixLanguage() {
  fisixLanguageObserver.disconnect();
  fisixApplyingTranslations = true;
  document.documentElement.lang = fisixLanguage;
  document.title = fisixLanguage === "en" ? "Fisix | Learn physics" : "Fisix | Aprende física";
  translateFisixNode(document.body);
  const selector = document.getElementById("languageSelect");
  if (selector && selector.value !== fisixLanguage) selector.value = fisixLanguage;
  const currentPage = document.querySelector(".page.active-page");
  if (currentPage) {
    const pageKey = currentPage.id.replace("page-", "");
    const title = pageTitles[pageKey];
    if (title) {
      $("#pageName").textContent = title;
      translateFisixNode($("#pageName"));
    }
  }
  fisixApplyingTranslations = false;
  fisixLanguageObserver.observe(document.body, {subtree:true, childList:true, characterData:true, attributes:true, attributeFilter:["placeholder","title","aria-label","data-prompt"]});
}

let fisixLanguageChangeInProgress = false;

async function translateExistingChatMessages(targetLanguage) {
  if (!activeChat?.messages?.length) return false;
  const assistantMessages = activeChat.messages.filter(message =>
    message.role === "assistant" && message.text &&
    !String(message.text).startsWith("No se pudo obtener una respuesta.") &&
    message.text !== "Consulta cancelada."
  );
  const needsTranslation = assistantMessages.filter(message => {
    const sourceLanguage = message.sourceLanguage || "es";
    return sourceLanguage !== targetLanguage && !message.translations?.[targetLanguage];
  });
  if (!needsTranslation.length) return false;
  if (!geminiApiKey && !configurarClaveGemini()) {
    toast(targetLanguage === "en"
      ? "Set your Gemini API key to translate the current answers."
      : "Configura tu API key de Gemini para traducir las respuestas actuales.");
    return false;
  }

  const languageName = targetLanguage === "en" ? "English" : "Spanish";
  toast(targetLanguage === "en" ? "Translating current answers…" : "Traduciendo las respuestas actuales…");
  for (const message of needsTranslation) {
    const prompt = `Translate the following educational physics assistant response into ${languageName}. This is a translation of an existing answer, not a new answer. Preserve its complete meaning, all details, paragraph structure, lists, Markdown, numbers, units, symbols, and every LaTeX expression exactly as written. Do not solve the problem again, add explanations, omit content, or change any mathematical notation. Return only the translated text.\n\nTEXT TO TRANSLATE:\n${message.text}`;
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": geminiApiKey },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.1 }
      })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error?.message || `Gemini translation failed (HTTP ${response.status}).`);
    const translated = data.candidates?.[0]?.content?.parts?.map(part => part.text || "").join("").trim();
    if (!translated) throw new Error("Gemini did not return the translated answer.");
    if (!message.translations) message.translations = {};
    message.translations[targetLanguage] = translated;
  }
  saveActiveChat();
  return true;
}

async function setFisixLanguage(language) {
  const nextLanguage = language === "en" ? "en" : "es";
  if (nextLanguage === fisixLanguage || fisixLanguageChangeInProgress) return;
  const previousLanguage = fisixLanguage;
  fisixLanguage = nextLanguage;
  try { localStorage.setItem("fisix-language", fisixLanguage); } catch {}
  applyFisixLanguage();

  if (activeChat?.messages?.some(message => message.role === "assistant" && message.text)) {
    fisixLanguageChangeInProgress = true;
    try {
      await translateExistingChatMessages(nextLanguage);
      // Rebuild the visible conversation using the cached translation while
      // keeping the original answer as the source for future language switches.
      if (activeChat?.id) await openSavedChat(activeChat.id);
    } catch (error) {
      console.error("No se pudieron traducir las respuestas existentes:", error);
      fisixLanguage = previousLanguage;
      try { localStorage.setItem("fisix-language", fisixLanguage); } catch {}
      applyFisixLanguage();
      const selector = document.getElementById("languageSelect");
      if (selector) selector.value = fisixLanguage;
      toast(fisixLanguage === "en"
        ? "Could not translate the current answers. The previous language was restored."
        : "No se pudieron traducir las respuestas actuales. Se restauró el idioma anterior.");
      return;
    } finally {
      fisixLanguageChangeInProgress = false;
    }
  }
  toast(fisixLanguage === "en" ? "Language changed to English." : "Idioma cambiado a español.");
}

const fisixLanguageObserver = new MutationObserver(records => {
  if (fisixApplyingTranslations || fisixLanguage !== "en") return;
  fisixLanguageObserver.disconnect();
  fisixApplyingTranslations = true;
  for (const record of records) {
    if (record.type === "childList") record.addedNodes.forEach(translateFisixNode);
    else if (record.type === "characterData") {
      // Text updated by the app is treated as a fresh Spanish source string.
      fisixOriginalText.set(record.target, record.target.data);
      translateFisixNode(record.target);
    } else if (record.type === "attributes") {
      const el = record.target;
      const attr = record.attributeName;
      let originals = fisixOriginalAttrs.get(el);
      if (!originals) { originals = {}; fisixOriginalAttrs.set(el, originals); }
      if (attr && ["placeholder", "title", "aria-label", "data-prompt"].includes(attr)) {
        originals[attr] = el.getAttribute(attr);
        translateFisixNode(el);
      }
    }
  }
  fisixApplyingTranslations = false;
  fisixLanguageObserver.observe(document.body, {subtree:true, childList:true, characterData:true, attributes:true, attributeFilter:["placeholder","title","aria-label","data-prompt"]});
});
fisixLanguageObserver.observe(document.body, {subtree:true, childList:true, characterData:true, attributes:true, attributeFilter:["placeholder","title","aria-label","data-prompt"]});
document.addEventListener("DOMContentLoaded", () => applyFisixLanguage());

const toast = (msg) => { const t=$("#toast"); t.textContent=translateFisixText(msg); t.classList.add("show"); clearTimeout(window.toastTimer); window.toastTimer=setTimeout(()=>t.classList.remove("show"),2600); };
const pageTitles={home:"Inicio",assistant:"Asistente IA",simulators:"Simuladores",quizzes:"Cuestionarios",formulas:"Fórmulas",calculator:"Calculadora",converter:"Conversor de unidades"};
function goPage(name){$$(".page").forEach(p=>p.classList.remove("active-page"));$("#page-"+name).classList.add("active-page");$$(".nav-item").forEach(b=>b.classList.toggle("active",b.dataset.page===name));$("#pageName").textContent=translateFisixText(pageTitles[name]);$("#sidebar").classList.remove("open");window.scrollTo(0,0);}
$$("[data-page]").forEach(b=>b.addEventListener("click",()=>goPage(b.dataset.page)));
$("#openSidebar").onclick=()=>$("#sidebar").classList.add("open");$("#closeSidebar").onclick=()=>$("#sidebar").classList.remove("open");
$("#languageSelect").addEventListener("change", e => setFisixLanguage(e.target.value));

// ===== Chat de Fisix conectado a Google Gemini =====
// DEMO: clave configurada directamente para evitar solicitarla al abrir Fisix.
// IMPORTANTE: al estar en el frontend público, cualquier visitante puede verla y usarla.
// Modelo de baja latencia para conversación educativa.
// Si necesitas razonamiento más avanzado, prueba gemini-3.8-flash
// y cambia GEMINI_THINKING_LEVEL a "low".
const GEMINI_MODEL = "gemini-3.5-flash-lite";
const GEMINI_THINKING_LEVEL = "low";
const GEMINI_HISTORY_MESSAGES = 30; // Hasta 15 intercambios previos por conversación.
const GEMINI_URL =
  `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:streamGenerateContent?alt=sse`;

let geminiApiKey = "AQ.Ab8RN6KJxRbbckwxb4YkemHaEeBYsEpyMSZNj1724GeQcz9CgA";
let chatHistory = []; // Contexto reciente que se envía a Gemini.
let activeChat = null;
const FISIX_CHATS_KEY = "fisix_saved_chats_v1";
const CHAT_TITLE_LIMIT = 30;
let currentFisixUser = null;
let savedChatRecords = [];

function chatsStorageKey() {
  return `${FISIX_CHATS_KEY}_${currentFisixUser || "guest"}`;
}

// Los archivos multimedia se guardan en IndexedDB (no en localStorage),
// para que las imágenes y notas de voz sigan disponibles al reabrir un chat.
const FISIX_MEDIA_DB = "fisix_media_v1";
let fisixMediaDbPromise = null;
function openFisixMediaDb() {
  if (!window.indexedDB) return Promise.reject(new Error("IndexedDB no está disponible en este navegador."));
  if (!fisixMediaDbPromise) {
    fisixMediaDbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(FISIX_MEDIA_DB, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains("media")) db.createObjectStore("media", { keyPath: "id" });
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("No se pudo abrir el almacenamiento multimedia."));
    });
  }
  return fisixMediaDbPromise;
}
async function saveChatMedia(blob, kind, chatId) {
  if (!blob) return null;
  const db = await openFisixMediaDb();
  const id = `${chatId}-${kind}-${window.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`}`;
  await new Promise((resolve, reject) => {
    const tx = db.transaction("media", "readwrite");
    tx.objectStore("media").put({ id, blob, kind, chatId, savedAt: Date.now() });
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error || new Error("No se pudo guardar el archivo multimedia."));
    tx.onabort = () => reject(tx.error || new Error("Se canceló el guardado multimedia."));
  });
  return id;
}
async function getChatMedia(id) {
  if (!id) return null;
  const db = await openFisixMediaDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction("media", "readonly").objectStore("media").get(id);
    request.onsuccess = () => resolve(request.result?.blob || null);
    request.onerror = () => reject(request.error || new Error("No se pudo recuperar el archivo multimedia."));
  });
}
async function deleteChatMedia(chatId) {
  try {
    const db = await openFisixMediaDb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction("media", "readwrite");
      const store = tx.objectStore("media");
      const request = store.openCursor();
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) return;
        if (cursor.value.chatId === chatId) cursor.delete();
        cursor.continue();
      };
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  } catch (error) { console.warn("No se pudieron limpiar los adjuntos del chat:", error); }
}

function loadSavedChats() {
  try {
    const data = JSON.parse(localStorage.getItem(chatsStorageKey()) || "[]");
    return Array.isArray(data) ? data.filter(c => c && c.id && Array.isArray(c.messages)) : [];
  } catch (error) {
    console.warn("No se pudo leer el historial local de Fisix:", error);
    return [];
  }
}

function persistSavedChats() {
  try {
    localStorage.setItem(chatsStorageKey(), JSON.stringify(savedChatRecords));
    return true;
  } catch (error) {
    console.warn("No se pudo guardar el historial local de Fisix:", error);
    toast("No se pudo guardar el chat. El almacenamiento del navegador podría estar lleno.");
    return false;
  }
}

function chatTitle(text) {
  const clean = String(text || "Nueva conversación").replace(/\s+/g, " ").trim();
  return clean.length > CHAT_TITLE_LIMIT ? clean.slice(0, CHAT_TITLE_LIMIT - 1) + "…" : clean;
}

function renderSavedChats() {
  const container = $("#savedChats");
  container.innerHTML = "";
  if (!savedChatRecords.length) {
    const empty = document.createElement("div");
    empty.className = "saved-empty";
    empty.textContent = fisixLanguage === "en" ? "Your chats will appear here when you start a conversation." : "Tus chats se guardarán aquí cuando comiences una conversación.";
    container.append(empty);
    return;
  }
  savedChatRecords.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
  savedChatRecords.forEach(chat => {
    const item = document.createElement("div");
    item.className = "saved-chat-row";
    const open = document.createElement("button");
    open.type = "button";
    open.className = "saved-chat-item" + (activeChat?.id === chat.id ? " active" : "");
    open.textContent = chat.title || "Conversación";
    open.title = chat.title || "Conversación";
    open.addEventListener("click", () => openSavedChat(chat.id));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "saved-chat-delete";
    remove.textContent = "×";
    remove.title = fisixLanguage === "en" ? "Delete chat" : "Eliminar chat";
    remove.setAttribute("aria-label", remove.title);
    remove.addEventListener("click", event => {
      event.stopPropagation();
      deleteSavedChat(chat.id);
    });
    item.append(open, remove);
    container.append(item);
  });
}

function saveActiveChat() {
  if (!activeChat || !activeChat.messages.length) return;
  activeChat.updatedAt = Date.now();
  const index = savedChatRecords.findIndex(c => c.id === activeChat.id);
  if (index >= 0) savedChatRecords[index] = activeChat;
  else savedChatRecords.unshift(activeChat);
  persistSavedChats();
  renderSavedChats();
}

function startNewChat() {
  ++chatRequestId;
  if (currentChatController) currentChatController.abort();
  currentChatController = null;
  setChatBusy(false);
  saveActiveChat();
  activeChat = null;
  chatHistory = [];
  $("#messages").innerHTML = "";
  $("#welcomeChat").style.display = "block";
  $("#chatInput").value = "";
  $("#chatInput").style.height = "auto";
  renderSavedChats();
  goPage("assistant");
}

async function openSavedChat(id) {
  const chat = savedChatRecords.find(c => c.id === id);
  if (!chat) return;
  ++chatRequestId;
  if (currentChatController) currentChatController.abort();
  currentChatController = null;
  setChatBusy(false);
  activeChat = chat;
  chatHistory = [];
  $("#messages").innerHTML = "";
  $("#welcomeChat").style.display = "none";
  for (const message of chat.messages) {
    let media = null;
    // Limpia etiquetas de adjuntos usadas por versiones anteriores del proyecto.
    const displayText = String(message.translations?.[fisixLanguage] || message.text || "")
      .replace(/\n\[Imagen:[^\]]*\]/g, "")
      .replace(/\n\[Audio adjunto\]/g, "")
      .trim();
    let historyParts = displayText ? [{ text: displayText }] : [];
    try {
      if (message.imageMediaId) {
        const imageBlob = await getChatMedia(message.imageMediaId);
        if (imageBlob) {
          media = { ...(media || {}), image: imageBlob };
          historyParts.push(await fileToInlinePart(new File([imageBlob], "fisix-image", { type: imageBlob.type || "image/jpeg" })));
        }
      }
      if (message.audioMediaId) {
        const audioBlob = await getChatMedia(message.audioMediaId);
        if (audioBlob) {
          media = { ...(media || {}), audio: audioBlob };
          historyParts.push(await fileToInlinePart(new File([audioBlob], "fisix-audio", { type: audioBlob.type || "audio/webm" })));
        }
      }
    } catch (error) {
      console.warn("No se pudo recuperar un adjunto del historial:", error);
    }
    addMessage(displayText, message.role === "user" ? "user" : "assistant", media);
    if (message.role === "user" && historyParts.length) appendGeminiHistory("user", historyParts);
    else if (message.role === "user" && (media?.image || media?.audio)) appendGeminiHistory("user", historyParts);
    else if (message.role === "assistant" && !String(message.text || "").startsWith("No se pudo obtener una respuesta.") && message.text !== "Consulta cancelada.") {
      appendGeminiHistory("model", historyParts);
    }
  }
  chatHistory = chatHistory.slice(-GEMINI_HISTORY_MESSAGES);
  renderSavedChats();
  goPage("assistant");
  $("#chatScroll").scrollTop = $("#chatScroll").scrollHeight;
}

function deleteSavedChat(id) {
  const chat = savedChatRecords.find(c => c.id === id);
  if (!chat) return;
  const confirmText = fisixLanguage === "en" ? `Delete the chat “${chat.title}”? This cannot be undone.` : `¿Eliminar la conversación “${chat.title}”? Esta acción no se puede deshacer.`;
  if (!window.confirm(confirmText)) return;
  savedChatRecords = savedChatRecords.filter(c => c.id !== id);
  deleteChatMedia(id);
  if (activeChat?.id === id) {
    ++chatRequestId;
    if (currentChatController) currentChatController.abort();
    currentChatController = null;
    setChatBusy(false);
    activeChat = null;
    chatHistory = [];
    $("#messages").innerHTML = "";
    $("#welcomeChat").style.display = "block";
  }
  persistSavedChats();
  renderSavedChats();
}

function ensureActiveChat(firstQuestion) {
  if (!activeChat) {
    activeChat = {
      id: (window.crypto?.randomUUID?.() || `chat-${Date.now()}-${Math.random().toString(16).slice(2)}`),
      title: chatTitle(firstQuestion),
      createdAt: Date.now(),
      updatedAt: Date.now(),
      messages: []
    };
  }
  if (!activeChat.messages.length) activeChat.title = chatTitle(firstQuestion);
}

let chatBusy = false;
let currentChatController = null;
let chatRequestId = 0;

function renderAssistantText(rawText) {
  // Convierte Markdown básico a HTML seguro y legible. Nunca inserta HTML de Gemini directamente.
  const escape = value => String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
  const inline = value => escape(value)
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/(?<!\*)\*([^*\n]+)\*(?!\*)/g, "<em>$1</em>")
    .replace(/`([^`]+)`/g, '<code>$1</code>');

  const lines = String(rawText || "").replace(/\r/g, "").split("\n");
  const blocks = [];
  let paragraph = [];
  let list = [];
  let mathBlock = null;
  const flushParagraph = () => {
    if (paragraph.length) {
      blocks.push(`<p>${paragraph.map(inline).join("<br>")}</p>`);
      paragraph = [];
    }
  };
  const flushList = () => {
    if (list.length) {
      blocks.push(`<ul>${list.map(item => `<li>${inline(item)}</li>`).join("")}</ul>`);
      list = [];
    }
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (mathBlock) {
      mathBlock.push(line);
      if (trimmed.includes("\\]")) {
        blocks.push(`<div class="math-display">${escape(mathBlock.join("\n"))}</div>`);
        mathBlock = null;
      }
      continue;
    }
    if (trimmed === "\\[") {
      flushParagraph(); flushList();
      mathBlock = [line];
      continue;
    }
    if (trimmed.startsWith("\\[") && trimmed.includes("\\]")) {
      flushParagraph(); flushList();
      blocks.push(`<div class="math-display">${escape(trimmed)}</div>`);
      continue;
    }
    if (!trimmed) { flushParagraph(); flushList(); continue; }
    const heading = trimmed.match(/^#{1,4}\s+(.+)$/);
    const bullet = trimmed.match(/^(?:[-*•]|\d+[.)])\s+(.+)$/);
    if (heading) {
      flushParagraph(); flushList();
      blocks.push(`<h3>${inline(heading[1])}</h3>`);
    } else if (bullet) {
      flushParagraph();
      list.push(bullet[1]);
    } else {
      flushList();
      paragraph.push(trimmed);
    }
  }
  if (mathBlock) blocks.push(`<div class="math-display">${escape(mathBlock.join("\n"))}</div>`);
  flushParagraph(); flushList();
  return blocks.join("");
}

const fisixMathJaxReady = new Promise(resolve => {
  if (window.MathJax?.typesetPromise) resolve();
  else window.addEventListener("fisix-mathjax-ready", resolve, { once: true });
});

async function typesetAssistantMath(element) {
  if (!element) return;
  try {
    await fisixMathJaxReady;
    if (!window.MathJax?.typesetPromise) return;
    window.MathJax.typesetClear?.([element]);
    await window.MathJax.typesetPromise([element]);
  } catch (error) {
    console.warn("No se pudieron renderizar algunas fórmulas LaTeX:", error);
  }
}

let fisixSpeechActiveButton = null;

function textoParaLectura(text) {
  return String(text || "")
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/\\\[([\s\S]*?)\\\]/g, " $1 ")
    .replace(/\\\(([\s\S]*?)\\\)/g, " $1 ")
    .replace(/\$\$([\s\S]*?)\$\$/g, " $1 ")
    .replace(/\$([^$\n]+)\$/g, " $1 ")
    .replace(/\\frac\{([^{}]+)\}\{([^{}]+)\}/g, "$1 dividido entre $2")
    .replace(/\\sqrt\{([^{}]+)\}/g, "raíz cuadrada de $1")
    .replace(/\\times|\\cdot/g, " por ")
    .replace(/\\pm/g, " más o menos ")
    .replace(/\\pi/g, " pi ")
    .replace(/\\(text|mathrm|mathbf|mathit)\{([^{}]*)\}/g, "$2")
    .replace(/\\(begin|end)\{[^{}]+\}/g, " ")
    .replace(/\\[a-zA-Z]+/g, " ")
    .replace(/[{}_^]/g, " ")
    .replace(/^\s{0,3}#{1,6}\s*/gm, "")
    .replace(/^\s*[-*+]\s+/gm, "")
    .replace(/^\s*\d+[.)]\s+/gm, "")
    .replace(/[*`>#]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function agregarControlesDeVoz(element, text) {
  element.querySelector(".speech-controls")?.remove();
  const plainText = textoParaLectura(text);
  if (!plainText || plainText === "Pensando…" || plainText === "Pensando...") return;

  const controls = document.createElement("div");
  controls.className = "speech-controls";
  const play = document.createElement("button");
  play.type = "button";
  play.className = "speech-play";
  play.textContent = "🔊 Escuchar";
  play.setAttribute("aria-label", "Escuchar respuesta en voz alta");
  const pause = document.createElement("button");
  pause.type = "button";
  pause.className = "speech-pause";
  pause.textContent = "Ⅱ Pausar";
  pause.hidden = true;
  const restart = document.createElement("button");
  restart.type = "button";
  restart.className = "speech-restart";
  restart.textContent = "↻ Desde el inicio";
  const stop = document.createElement("button");
  stop.type = "button";
  stop.className = "speech-stop";
  stop.textContent = "Detener";
  stop.hidden = true;
  const progress = document.createElement("input");
  progress.type = "range";
  progress.className = "speech-progress";
  progress.min = "0"; progress.max = "1000"; progress.value = "0";
  progress.setAttribute("aria-label", "Avanzar o retroceder en la lectura");
  const time = document.createElement("span");
  time.className = "speech-time";
  time.textContent = "0:00 / " + formatoTiempoVoz(plainText.length / 15);
  controls.append(play, pause, restart, stop, progress, time);

  let currentUtterance = null;
  let currentPosition = 0;
  let utteranceStartPosition = 0;
  let isPlaying = false;
  let isPaused = false;
  let isSeeking = false;
  let seekWasPlaying = false;
  let seekWasPaused = false;
  const estimatedDuration = Math.max(1, plainText.length / 15);
  const updateProgress = (position) => {
    currentPosition = Math.max(0, Math.min(plainText.length, position));
    progress.value = String(Math.round(currentPosition / Math.max(1, plainText.length) * 1000));
    time.textContent = `${formatoTiempoVoz(currentPosition / Math.max(1, plainText.length) * estimatedDuration)} / ${formatoTiempoVoz(estimatedDuration)}`;
  };
  const resetControls = () => {
    isPlaying = false; isPaused = false;
    play.hidden = false; pause.hidden = true; stop.hidden = true;
    play.textContent = "🔊 Escuchar";
    if (fisixSpeechActiveButton === play) fisixSpeechActiveButton = null;
  };
  const speakFrom = (position = 0) => {
    if (!("speechSynthesis" in window) || !("SpeechSynthesisUtterance" in window)) {
      toast("Tu navegador no admite lectura en voz alta."); return;
    }
    window.speechSynthesis.cancel();
    currentPosition = Math.max(0, Math.min(plainText.length, position));
    utteranceStartPosition = currentPosition;
    updateProgress(currentPosition);
    const remainingText = plainText.slice(currentPosition).trimStart();
    if (!remainingText) { updateProgress(plainText.length); resetControls(); return; }
    const utterance = new SpeechSynthesisUtterance(remainingText);
    currentUtterance = utterance;
    utterance.lang = fisixLanguage === "en" ? "en-US" : "es-PE";
    utterance.rate = 0.95;
    utterance.pitch = 1;
    const voices = window.speechSynthesis.getVoices();
    const preferred = voices.find(v => v.lang.toLowerCase() === utterance.lang.toLowerCase())
      || voices.find(v => v.lang.toLowerCase().startsWith(fisixLanguage === "en" ? "en" : "es"));
    if (preferred) utterance.voice = preferred;
    isPlaying = true; isPaused = false;
    fisixSpeechActiveButton = play;
    play.hidden = true; pause.hidden = false; stop.hidden = false;
    pause.textContent = "Ⅱ Pausar";
    utterance.onboundary = (event) => {
      // charIndex siempre es relativo al texto de ESTA locución; no se debe sumar
      // a la posición que va cambiando, porque eso adelanta artificialmente la barra.
      if (currentUtterance === utterance && !isSeeking && typeof event.charIndex === "number") {
        updateProgress(utteranceStartPosition + event.charIndex);
      }
    };
    utterance.onend = () => {
      if (currentUtterance !== utterance) return;
      updateProgress(plainText.length);
      currentUtterance = null;
      resetControls();
    };
    utterance.onerror = (event) => {
      if (currentUtterance !== utterance) return;
      if (event.error !== "canceled" && event.error !== "interrupted") toast("No se pudo completar la lectura en voz alta.");
      currentUtterance = null;
      if (!isPaused) resetControls();
    };
    window.speechSynthesis.speak(utterance);
  };
  play.addEventListener("click", () => speakFrom(currentPosition));
  pause.addEventListener("click", () => {
    if (window.speechSynthesis.speaking && !window.speechSynthesis.paused) {
      window.speechSynthesis.pause(); isPaused = true; isPlaying = false;
      pause.textContent = "▶ Continuar";
    } else if (window.speechSynthesis.paused) {
      window.speechSynthesis.resume(); isPaused = false; isPlaying = true;
      pause.textContent = "Ⅱ Pausar";
    }
  });
  restart.addEventListener("click", () => speakFrom(0));
  stop.addEventListener("click", () => {
    window.speechSynthesis.cancel(); updateProgress(0); resetControls();
  });
  progress.addEventListener("pointerdown", () => {
    isSeeking = true;
    seekWasPlaying = isPlaying && !isPaused;
    seekWasPaused = isPaused;
    if (seekWasPlaying && window.speechSynthesis.speaking) window.speechSynthesis.pause();
  });
  progress.addEventListener("input", () => {
    const target = Math.round(Number(progress.value) / 1000 * plainText.length);
    updateProgress(target); // Solo mueve la posición visual mientras se arrastra.
  });
  const finishSeeking = () => {
    if (!isSeeking) return;
    const target = Math.round(Number(progress.value) / 1000 * plainText.length);
    const resumeAfterSeek = seekWasPlaying;
    const remainPaused = seekWasPaused;
    isSeeking = false;
    window.speechSynthesis.cancel();
    currentUtterance = null;
    updateProgress(target);
    if (resumeAfterSeek || remainPaused) {
      speakFrom(target);
      if (remainPaused) {
        window.speechSynthesis.pause();
        isPaused = true; isPlaying = false;
        pause.textContent = "▶ Continuar";
      }
    } else {
      resetControls();
    }
  };
  progress.addEventListener("change", finishSeeking);
  progress.addEventListener("pointerup", finishSeeking);
  progress.addEventListener("pointercancel", finishSeeking);
  progress.addEventListener("keydown", (event) => {
    if (["ArrowLeft", "ArrowRight", "Home", "End", "PageUp", "PageDown"].includes(event.key)) {
      isSeeking = true;
      seekWasPlaying = isPlaying && !isPaused;
      seekWasPaused = isPaused;
    }
  });
  element.append(controls);
}

function formatoTiempoVoz(seconds) {
  const safe = Math.max(0, Math.floor(Number(seconds) || 0));
  return `${Math.floor(safe / 60)}:${String(safe % 60).padStart(2, "0")}`;
}

function setAssistantBubbleContent(element, text) {
  if (window.MathJax?.typesetClear) window.MathJax.typesetClear([element]);
  element.innerHTML = renderAssistantText(text);
  agregarControlesDeVoz(element, text);
  typesetAssistantMath(element);
}

function addMessage(text, who, media = null) {
  const wrap = document.createElement("div");
  wrap.className = "message " + who;
  const av = document.createElement("div");
  av.className = "message-avatar";
  av.textContent = who === "user" ? "T" : "✧";
  const bubble = document.createElement("div");
  bubble.className = "message-bubble";
  if (who === "assistant") {
    setAssistantBubbleContent(bubble, text);
  } else {
    if (text) bubble.textContent = text;
    if (media?.image) {
      const imageUrl = URL.createObjectURL(media.image);
      const image = document.createElement("img");
      image.className = "chat-image-attachment";
      image.src = imageUrl;
      image.alt = "Imagen enviada en la conversación";
      image.loading = "lazy";
      image.title = "Abrir imagen";
      image.addEventListener("click", () => window.open(imageUrl, "_blank", "noopener"));
      bubble.append(image);
    }
    if (media?.audio) {
      const audioUrl = URL.createObjectURL(media.audio);
      const voice = document.createElement("div");
      voice.className = "chat-voice-message";
      const play = document.createElement("button");
      play.type = "button"; play.className = "voice-play"; play.textContent = "▶";
      play.setAttribute("aria-label", "Reproducir mensaje de voz");
      const audio = document.createElement("audio");
      audio.src = audioUrl; audio.preload = "metadata";
      const wave = document.createElement("span"); wave.className = "voice-wave";
      wave.setAttribute("aria-hidden", "true");
      wave.innerHTML = Array.from({length:28}, (_,i) => `<i style="--h:${8 + ((i*13+7)%19)}px"></i>`).join("");
      const duration = document.createElement("small"); duration.textContent = "Nota de voz";
      audio.addEventListener("loadedmetadata", () => { const d=audio.duration; if(Number.isFinite(d)) duration.textContent = `${Math.floor(d/60)}:${String(Math.floor(d%60)).padStart(2,"0")}`; });
      play.onclick = async () => {
        if (audio.paused) {
          try { await audio.play(); play.textContent = "Ⅱ"; }
          catch { toast("No se pudo reproducir este audio en el navegador."); }
        } else { audio.pause(); play.textContent = "▶"; }
      };
      audio.addEventListener("ended", () => { play.textContent="▶"; });
      audio.addEventListener("pause", () => { if (!audio.ended) play.textContent="▶"; });
      voice.append(play, wave, duration, audio);
      bubble.append(voice);
      audio.addEventListener("error", () => { duration.textContent = "Audio no disponible"; });
    }
  }
  wrap.append(av, bubble);
  $("#messages").append(wrap);
  $("#chatScroll").scrollTop = $("#chatScroll").scrollHeight;
  return bubble;
}

function configurarClaveGemini() {
  const valor = window.prompt(
    fisixLanguage === "en"
      ? "Enter your Gemini API key (for this tab only).\nIt is not saved in app.js, but it will be visible in browser network requests:"
      : "Introduce tu API key de Gemini (solo para esta pestaña).\\nNo se guarda en app.js, pero será visible en las solicitudes del navegador:",
    ""
  );
  if (valor === null) return false; // Canceló el cuadro de diálogo.
  const clave = valor.trim();
  if (!clave) {
    toast("No se ingresó una API key.");
    return false;
  }
  geminiApiKey = clave;
  toast("Clave de Gemini configurada para esta pestaña.");
  return true;
}

// No se muestra un botón de configuración de Gemini junto a «Nuevo chat».
// Si todavía no hay API key, Fisix la solicita automáticamente al enviar la primera pregunta.

function setChatBusy(busy) {
  chatBusy = busy;
  const submit = $("#chatForm").querySelector('button[type="submit"]') ||
    $("#chatForm").querySelector("button");
  if (submit) submit.disabled = busy;
  $$(".prompt-card").forEach(b => { b.disabled = busy; });
}

// Mantiene el contexto real de la conversación. Si una consulta anterior falló,
// los mensajes consecutivos del estudiante se agrupan en un único turno user válido.
function appendGeminiHistory(role, parts) {
  const safeParts = (Array.isArray(parts) ? parts : []).filter(Boolean);
  const last = chatHistory[chatHistory.length - 1];
  if (last?.role === role) last.parts.push(...safeParts);
  else chatHistory.push({ role, parts: safeParts });
  if (chatHistory.length > GEMINI_HISTORY_MESSAGES) {
    chatHistory = chatHistory.slice(-GEMINI_HISTORY_MESSAGES);
    while (chatHistory.length && chatHistory[0].role === "model") chatHistory.shift();
  }
}

function normalizeGeminiHistory(messages) {
  const normalized = [];
  for (const message of messages || []) {
    if (!message || !["user", "model"].includes(message.role)) continue;
    const parts = Array.isArray(message.parts) ? message.parts.filter(Boolean) : [];
    if (!parts.length) continue;
    const previous = normalized[normalized.length - 1];
    if (previous?.role === message.role) previous.parts.push(...parts);
    else normalized.push({ role: message.role, parts: [...parts] });
  }
  while (normalized.length && normalized[0].role !== "user") normalized.shift();
  return normalized.slice(-GEMINI_HISTORY_MESSAGES);
}

// ===== Instrucciones generales del tutor Fisix =====
function buildFisixSystemInstruction() {
  const baseEs = `IDIOMA OBLIGATORIO: responde siempre en español. Esta selección tiene prioridad sobre el idioma de los mensajes anteriores, documentos adjuntos o ejemplos. Si el usuario cambia el selector a inglés, la siguiente respuesta debe estar completamente en inglés; si lo cambia a español, debe estar completamente en español. No mezcles idiomas salvo que el usuario lo solicite.

Eres Fisix, un tutor especializado en física universitaria. Responde en español claro y conserva el contexto de toda la conversación. Interpreta seguimientos breves como «¿por qué?», «no entendí», «ese paso» o «explícalo otra vez» usando el tema y los mensajes anteriores. Si hubo un error, corrígelo directamente y explica qué estaba mal. Ajusta la profundidad a la pregunta y a lo que el estudiante demuestre necesitar; no agregues contenido solo para alargar la respuesta.

FORMATO: escribe con párrafos breves y organización limpia. No uses encabezados Markdown #, tablas ni bloques de código salvo que se pidan. Escribe toda expresión matemática en LaTeX válido: \\( ... \\) en línea y \\[ ... \\] en bloque. Usa unidades SI cuando corresponda.

FÍSICA: puedes ayudar con mecánica, electricidad, magnetismo, óptica, ondas, termodinámica y los temas del temario de Fisix. Si la consulta no guarda relación razonable con física, explica amablemente que Fisix está especializado en esa materia.

IMÁGENES Y AUDIO: analiza las imágenes adjuntas y resuelve lo que se vea. Interpreta el contenido hablado de los audios y responde a la pregunta; transcribe solo si lo solicitan.`;
  const baseEn = `MANDATORY LANGUAGE: always answer in English. This selection takes priority over the language of earlier messages, attached documents, or examples. If the user switches the selector to Spanish, the next answer must be entirely in Spanish; if they switch it to English, it must be entirely in English. Do not mix languages unless requested.

You are Fisix, a university-level physics tutor. Answer in clear English and preserve the full conversation context. Interpret short follow-ups such as “why?”, “I did not understand”, “that step”, or “explain again” using earlier messages and the current topic. If an earlier answer was wrong, correct it directly and explain the mistake. Adjust depth to the question and what the student appears to need; never add content merely to make an answer longer.

FORMAT: use concise paragraphs and clean structure. Avoid Markdown # headings, tables, and code blocks unless requested. Write every mathematical expression in valid LaTeX: \\( ... \\) inline and \\[ ... \\] display. Use SI units where appropriate.

PHYSICS: help with mechanics, electricity, magnetism, optics, waves, thermodynamics, and related university physics topics. Politely explain that Fisix specializes in physics if a request is unrelated.

IMAGES AND AUDIO: inspect attached images and solve what is visible. Interpret spoken questions in audio and answer them; transcribe only when requested.`;
  return fisixLanguage === "en" ? baseEn : baseEs;
}

async function consultarGemini(mensaje, historial = chatHistory, signal, onChunk = () => {}, mediaParts = []) {
  if (!geminiApiKey && !configurarClaveGemini()) {
    throw new Error("Debes configurar tu API key para consultar Gemini.");
  }

  // Enviamos el historial reciente de esta conversación y el mensaje actual.
  const contents = normalizeGeminiHistory([
    ...(historial || []),
    { role: "user", parts: [{ text: mensaje }, ...mediaParts] }
  ]);

  let response;
  try {
    response = await fetch(GEMINI_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": geminiApiKey
      },
      body: JSON.stringify({
        systemInstruction: {
          parts: [{ text: buildFisixSystemInstruction() }]
        },
        contents,
        generationConfig: {
          thinkingConfig: { thinkingLevel: GEMINI_THINKING_LEVEL }
        }
      }),
      signal
    });
  } catch (error) {
    if (error.name === "AbortError") throw error;
    throw new Error(
      "No se pudo conectar a Gemini. Verifica tu conexión. " +
      "Si aparece un error de CORS, puede ser necesario revisar " +
      "las restricciones de acceso desde el navegador."
    );
  }

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    if (response.status === 400) {
      throw new Error(data.error?.message || "Solicitud incorrecta. Revisa los datos enviados.");
    }
    if (response.status === 401 || response.status === 403) {
      throw new Error(
        "La API rechazó la clave o no tiene permiso para usar Gemini. " +
        "Vuelve a enviar tu pregunta para introducir una clave válida."
      );
    }
    if (response.status === 404) {
      throw new Error(`El modelo ${GEMINI_MODEL} no está disponible para esta clave.`);
    }
    if (response.status === 429) {
      throw new Error("Límite de solicitudes de Gemini alcanzado. Inténtalo más tarde.");
    }
    if (response.status === 503) {
      throw new Error("Gemini está saturado temporalmente (HTTP 503). Vuelve a intentarlo.");
    }
    throw new Error(data.error?.message || `Error de Gemini (HTTP ${response.status}).`);
  }

  if (!response.body) {
    throw new Error("Este navegador no permite recibir la respuesta por fragmentos.");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let pending = "";
  let fullText = "";

  // El servicio emite Server-Sent Events: cada línea «data:» contiene un
  // fragmento JSON con el texto generado hasta ese momento.
  // Se procesan líneas completas para soportar fragmentos TCP arbitrarios.
  function procesarLinea(linea) {
    if (!linea.startsWith("data:")) return;
    const dataLine = linea.slice(5).trim();
    if (!dataLine || dataLine === "[DONE]") return;
    let event;
    try {
      event = JSON.parse(dataLine);
    } catch {
      throw new Error("Se recibió un fragmento inválido de Gemini.");
    }
    if (event.error) throw new Error(event.error.message || "Error en el stream de Gemini.");
    const text = event.candidates?.[0]?.content?.parts
      ?.filter(part => typeof part.text === "string" && !part.thought)
      .map(part => part.text).join("") || "";
    if (text) {
      fullText += text;
      onChunk(fullText);
    }
  }

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      pending += decoder.decode(value, { stream: true });
      let newlineAt;
      while ((newlineAt = pending.indexOf("\n")) !== -1) {
        const linea = pending.slice(0, newlineAt).replace(/\r$/, "");
        pending = pending.slice(newlineAt + 1);
        procesarLinea(linea);
      }
    }
    pending += decoder.decode();
    if (pending.trim()) procesarLinea(pending.trim());
  } finally {
    reader.releaseLock();
  }

  if (!fullText.trim()) {
    throw new Error("Gemini no devolvió texto; la solicitud puede haber sido bloqueada.");
  }
  return fullText.trim();
}

// Alias opcional, por si en otro fragmento del proyecto se usa gemini.consultar().
const gemini = { consultar: consultarGemini };

// Archivos adjuntos del mensaje actual: imagen y grabación de audio.
let pendingImage = null;
let pendingAudio = null;
let mediaRecorder = null;
let audioChunks = [];
let recordingStartedAt = 0;
let recordingTimer = null;
let pendingImagePreviewUrl = null;

function fileToInlinePart(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = String(reader.result || "");
      const comma = dataUrl.indexOf(",");
      if (comma < 0) return reject(new Error("No se pudo leer el archivo adjunto."));
      resolve({ inlineData: { mimeType: file.type || "application/octet-stream", data: dataUrl.slice(comma + 1) } });
    };
    reader.onerror = () => reject(new Error("No se pudo leer el archivo adjunto."));
    reader.readAsDataURL(file);
  });
}

function clearPendingImagePreview() {
  if (pendingImagePreviewUrl) URL.revokeObjectURL(pendingImagePreviewUrl);
  pendingImagePreviewUrl = null;
}

function updateAttachmentPreview() {
  const box = $("#attachmentPreview");
  box.replaceChildren();
  box.hidden = !pendingImage;
  if (!pendingImage) {
    clearPendingImagePreview();
    return;
  }

  clearPendingImagePreview();
  pendingImagePreviewUrl = URL.createObjectURL(pendingImage);
  const thumb = document.createElement("img");
  thumb.className = "composer-image-preview";
  thumb.src = pendingImagePreviewUrl;
  thumb.alt = "Vista previa de la imagen que se enviará";
  const details = document.createElement("div");
  details.className = "attachment-details";
  const name = document.createElement("strong");
  name.textContent = pendingImage.name || "Imagen";
  const hint = document.createElement("small");
  hint.textContent = `${formatSize(pendingImage.size)} · Se enviará en el chat`;
  details.append(name, hint);
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "remove-attachment";
  remove.textContent = "×";
  remove.title = "Quitar imagen";
  remove.setAttribute("aria-label", "Quitar imagen adjunta");
  remove.onclick = () => {
    pendingImage = null;
    updateAttachmentPreview();
  };
  box.append(thumb, details, remove);
}

async function extractDocumentText(file) {
  const ext = file.name.split(".").pop().toLowerCase();
  if (ext === "txt") return await file.text();
  if (ext === "pdf") {
    if (!window.pdfjsLib) throw new Error("No se pudo cargar el lector PDF. Revisa tu conexión.");
    pdfjsLib.GlobalWorkerOptions.workerSrc = "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";
    const pdf = await pdfjsLib.getDocument({ data: await file.arrayBuffer() }).promise;
    const pages = [];
    for (let n = 1; n <= pdf.numPages; n++) {
      const page = await pdf.getPage(n);
      const content = await page.getTextContent();
      pages.push(content.items.map(item => item.str).join(" "));
    }
    return pages.join("\n");
  }
  if (ext === "pptx") {
    if (!window.JSZip) throw new Error("No se pudo cargar el lector PPTX. Revisa tu conexión.");
    const archive = await JSZip.loadAsync(await file.arrayBuffer());
    const slideNames = Object.keys(archive.files).filter(name => /^ppt\/slides\/slide\d+\.xml$/.test(name)).sort((a,b) => Number(a.match(/slide(\d+)/)[1]) - Number(b.match(/slide(\d+)/)[1]));
    const slides = [];
    for (const name of slideNames) { const xml = await archive.files[name].async("text"); const doc = new DOMParser().parseFromString(xml, "application/xml"); slides.push([...doc.getElementsByTagName("a:t")].map(node => node.textContent).join(" ")); }
    return slides.join("\n\n");
  }
  if (ext === "docx") {
    if (!window.mammoth) throw new Error("No se pudo cargar el lector DOCX. Revisa tu conexión.");
    const result = await mammoth.extractRawText({ arrayBuffer: await file.arrayBuffer() });
    return result.value || "";
  }
  throw new Error("Este formato aún no tiene extracción de texto. Usa PDF, DOCX, PPTX o TXT.");
}

async function readAsInlinePart(blob, mimeType) {
  const named = new File([blob], "fisix-audio." + (mimeType.includes("ogg") ? "ogg" : "webm"), { type: mimeType });
  return fileToInlinePart(named);
}


async function sendChat(text) {
  const q = String(text || "").trim();
  if (!q && !pendingImage && !pendingAudio) return;
  if (chatBusy) {
    toast("Espera a que Gemini termine de responder.");
    return;
  }
  // Pedir la clave antes de modificar la interfaz o el historial.
  if (!geminiApiKey && !configurarClaveGemini()) {
    if (pendingAudio) $("#audioStatus").textContent = "Audio listo; pulsa enviar cuando configures tu clave de Gemini.";
    return;
  }

  const requestId = ++chatRequestId;
  const controller = new AbortController();
  currentChatController = controller;
  setChatBusy(true);

  $("#welcomeChat").style.display = "none";
  const messageImage = pendingImage;
  const messageAudio = pendingAudio;
  const shownQuestion = q || (messageImage ? "Analiza esta imagen de física." : "");
  addMessage(shownQuestion, "user", { image: messageImage, audio: messageAudio });
  // El adjunto pasa a ser parte del mensaje del chat: desaparece de la barra de escritura.
  pendingImage = null;
  pendingAudio = null;
  updateAttachmentPreview();
  $("#audioStatus").textContent = "";
  $("#chatInput").value = "";
  $("#chatInput").style.height = "auto";
  ensureActiveChat(shownQuestion || (messageAudio ? "Mensaje de voz" : "Imagen adjunta"));
  const chatForThisRequest = activeChat;
  const userMessageRecord = {
    role: "user",
    text: shownQuestion,
    timestamp: Date.now()
  };
  chatForThisRequest.messages.push(userMessageRecord);

  const answerBubble = addMessage("Pensando…", "assistant");
  answerBubble.classList.add("thinking-message");
  let mediaParts = [];
  let preguntaConFuentes = q || (messageImage ? "Analiza esta imagen de física." : messageAudio ? "Interpreta este mensaje de voz y responde a su contenido." : shownQuestion);
  try {
    const inicio = performance.now();
    let primerFragmento = false;
    // Persistir el Blob original en IndexedDB y guardar solo su identificador en el chat.
    try {
      if (messageImage) userMessageRecord.imageMediaId = await saveChatMedia(messageImage, "image", chatForThisRequest.id);
      if (messageAudio) userMessageRecord.audioMediaId = await saveChatMedia(messageAudio, "audio", chatForThisRequest.id);
    } catch (storageError) {
      console.warn("No se pudo guardar el adjunto para futuras sesiones:", storageError);
      toast("El mensaje se enviará, pero el adjunto no pudo guardarse para el historial. Revisa el espacio del navegador.");
    }
    if (activeChat?.id === chatForThisRequest.id) saveActiveChat();
    mediaParts = [];
    if (messageImage) mediaParts.push(await fileToInlinePart(messageImage));
    if (messageAudio) mediaParts.push(await fileToInlinePart(new File([messageAudio], "fisix-audio.webm", { type: messageAudio.type || "audio/webm" })));
    const promptText = q || (messageImage ? "Analiza esta imagen de física." : messageAudio ? "Interpreta este mensaje de voz y responde a su contenido." : shownQuestion);
    preguntaConFuentes = [promptText, ...sources.filter(f => f.extractedText).map(f => `\n\nDOCUMENTO ${f.name}:\n${f.extractedText.slice(0, 18000)}`)].join("");
    const respuesta = await consultarGemini(preguntaConFuentes, chatHistory, controller.signal, textoParcial => {
      if (requestId !== chatRequestId) return;
      if (!primerFragmento) {
        console.info(`Gemini: primer texto en ${((performance.now() - inicio) / 1000).toFixed(2)} s`);
        primerFragmento = true;
      }
      answerBubble.classList.remove("thinking-message");
      setAssistantBubbleContent(answerBubble, textoParcial);
      $("#chatScroll").scrollTop = $("#chatScroll").scrollHeight;
    }, mediaParts);
    console.info(`Gemini: respuesta completa en ${((performance.now() - inicio) / 1000).toFixed(2)} s`);
    if (requestId !== chatRequestId) return; // Se limpió el chat en esta espera.
    answerBubble.classList.remove("thinking-message");
    setAssistantBubbleContent(answerBubble, respuesta);
    chatForThisRequest.messages.push({
      role: "assistant", text: respuesta, sourceLanguage: fisixLanguage,
      translations: { [fisixLanguage]: respuesta }, timestamp: Date.now()
    });
    if (activeChat?.id === chatForThisRequest.id) saveActiveChat();
    appendGeminiHistory("user", [{ text: preguntaConFuentes }, ...mediaParts]);
    appendGeminiHistory("model", [{ text: respuesta }]);
  } catch (error) {
    if (requestId !== chatRequestId) return;
    if (error.name === "AbortError") {
      answerBubble.classList.remove("thinking-message");
      answerBubble.textContent = "Consulta cancelada.";
      chatForThisRequest.messages.push({ role: "assistant", text: "Consulta cancelada.", timestamp: Date.now() });
    } else {
      answerBubble.classList.remove("thinking-message");
      const errorText = "No se pudo obtener una respuesta.\n" + error.message;
      answerBubble.textContent = errorText;
      chatForThisRequest.messages.push({ role: "assistant", text: errorText, timestamp: Date.now() });
    }
    // Aunque Gemini falle, conservamos la pregunta y los adjuntos en el contexto.
    // Así, si el estudiante dice «inténtalo de nuevo», Fisix sabe a qué se refiere.
    appendGeminiHistory("user", [{ text: preguntaConFuentes }, ...mediaParts]);
    if (activeChat?.id === chatForThisRequest.id) saveActiveChat();
  } finally {
    if (requestId === chatRequestId) {
      currentChatController = null;
      setChatBusy(false);
      $("#chatScroll").scrollTop = $("#chatScroll").scrollHeight;
    }
  }
}

$("#chatForm").addEventListener("submit", e => {
  e.preventDefault();
  // Si el estudiante pulsa enviar mientras graba, detener y enviar audio + texto juntos.
  if (mediaRecorder?.state === "recording") {
    $("#audioStatus").textContent = "Preparando tu nota de voz…";
    mediaRecorder.stop();
    return;
  }
  sendChat($("#chatInput").value);
});
$("#chatInput").addEventListener("input", e => {
  e.target.style.height = "auto";
  e.target.style.height = Math.min(e.target.scrollHeight, 120) + "px";
});
$$(".prompt-card").forEach(b => b.onclick = () => sendChat(b.dataset.prompt));
$("#clearChat").onclick = startNewChat;
$(".new-chat").onclick = startNewChat;
renderSavedChats();
$("#chatAttach").onclick = () => $("#chatFileInput").click();
$("#chatFileInput").addEventListener("change", e => {
  const file = e.target.files?.[0];
  if (!file) return;
  const supportedImageTypes = ["image/jpeg", "image/png", "image/webp"];
  if (!supportedImageTypes.includes(file.type)) {
    toast("Formato no compatible. Usa una imagen JPG, PNG o WEBP.");
  } else if (file.size > 8 * 1024 * 1024) {
    toast("La imagen supera los 8 MB. Reduce su tamaño e inténtalo nuevamente.");
  } else {
    pendingImage = file;
    updateAttachmentPreview();
  }
  e.target.value = "";
});

$("#recordAudio").addEventListener("click", async () => {
  const status = $("#audioStatus");
  if (mediaRecorder?.state === "recording") {
    status.textContent = "Preparando tu nota de voz…";
    mediaRecorder.stop();
    return;
  }
  if (chatBusy) { toast("Espera a que Fisix termine de responder antes de grabar otro audio."); return; }
  if (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder) {
    toast("Tu navegador no permite grabar audio. Prueba Firefox o Chrome actualizado y habilita el micrófono."); return;
  }
  let stream = null;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const mime = ["audio/webm;codecs=opus", "audio/ogg;codecs=opus", "audio/webm", "audio/ogg"].find(t => MediaRecorder.isTypeSupported(t)) || "";
    const recorder = new MediaRecorder(stream, mime ? { mimeType: mime } : undefined);
    mediaRecorder = recorder;
    audioChunks = [];
    recorder.ondataavailable = event => { if (event.data.size) audioChunks.push(event.data); };
    recorder.onstop = () => {
      const type = recorder.mimeType || "audio/webm";
      const voiceBlob = new Blob(audioChunks, { type });
      stream.getTracks().forEach(track => track.stop());
      $("#recordAudio").classList.remove("recording");
      $("#recordAudio").textContent = "🎙";
      $("#recordAudio").title = "Grabar pregunta por audio";
      $("#recordAudio").setAttribute("aria-label", "Grabar pregunta por audio");
      status.classList.remove("is-recording");
      if (recordingTimer) clearInterval(recordingTimer);
      recordingTimer = null;
      recordingStartedAt = 0;
      if (!voiceBlob.size) {
        status.textContent = "";
        toast("No se capturó audio. Inténtalo nuevamente.");
        return;
      }
      pendingAudio = voiceBlob;
      status.classList.remove("is-recording");
      status.textContent = "Enviando nota de voz al chat…";
      // Al detener la grabación, la nota aparece como una burbuja y se envía automáticamente.
      sendChat($("#chatInput").value);
    };
    recorder.start();
    recordingStartedAt = Date.now();
    $("#recordAudio").classList.add("recording");
    $("#recordAudio").textContent = "■";
    $("#recordAudio").title = "Detener y enviar nota de voz";
    $("#recordAudio").setAttribute("aria-label", "Detener y enviar nota de voz");
    const updateRecordingStatus = () => {
      const seconds = Math.floor((Date.now() - recordingStartedAt) / 1000);
      const time = `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
      status.classList.add("is-recording");
    status.textContent = `● Grabando ${time} · Pulsa ■ para enviar`;
    };
    updateRecordingStatus();
    recordingTimer = setInterval(updateRecordingStatus, 500);
  } catch (error) {
    stream?.getTracks?.().forEach(track => track.stop());
    $("#audioStatus").classList.remove("is-recording");
    toast("No se pudo acceder al micrófono. Revisa los permisos del navegador.");
  }
});

// Sources: files remain in the current browser session only; no file contents are sent anywhere.
let sources=[];
function renderSources(){const list=$("#sourceList");$("#sourceCount").textContent=sources.length;if(!sources.length){list.innerHTML='<div class="no-sources">Aún no has agregado fuentes.</div>';return;}list.innerHTML="";sources.forEach((f,i)=>{const row=document.createElement("div");row.className="source-file";const ext=f.name.split(".").pop().toUpperCase();row.innerHTML=`<div class="file-icon">${ext.slice(0,4)}</div><div class="file-meta"><strong title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</strong><small>${f.reading ? "Leyendo documento…" : escapeHtml(f.readError || (f.extractedText ? "Texto extraído · " + formatSize(f.size) : formatSize(f.size)))}</small></div><button class="remove-file" aria-label="Quitar archivo">×</button>`;row.querySelector("button").onclick=()=>{sources.splice(i,1);renderSources();};list.append(row);});}
function escapeHtml(x){return x.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function formatSize(n){return n<1024?n+" B":(n/1024).toFixed(1)+" KB";}
$("#sourceUpload").addEventListener("change", async e => {
  const allowed = ["pdf", "docx", "pptx", "txt"];
  for (const file of [...e.target.files]) {
    const ext = file.name.split(".").pop().toLowerCase();
    if (!allowed.includes(ext)) { toast(`Por ahora el lector extrae PDF, DOCX, PPTX y TXT: ${file.name}`); continue; }
    const sourceRecord = { file, name: file.name, size: file.size, extractedText: "", reading: true };
    sources.push(sourceRecord); renderSources();
    try { sourceRecord.extractedText = await extractDocumentText(file); sourceRecord.reading = false; sourceRecord.readError = sourceRecord.extractedText.trim() ? "" : "No se encontró texto seleccionable (puede ser un PDF escaneado)."; }
    catch (error) { sourceRecord.reading = false; sourceRecord.readError = error.message; toast(error.message); }
    renderSources();
  }
  e.target.value = "";
});

function gaussEnclosed(v){return v.chargePosition==="outside"?0:v.charge;}
function waveMedium(v){const n=v.medium==="water"?1.33:v.medium==="glass"?1.5:1;return {n,label:v.medium==="water"?"Agua":v.medium==="glass"?"Vidrio":"Vacío",speed:3e8/n};}
// Óptica geométrica: convención cartesiana para espejos esféricos.
function mirrorPhysics(v){
 const type=v.mirrorType||"concave",do_=Math.max(.1,v.distance),f=type==="concave"?v.focal:type==="convex"?-v.focal:Infinity;
 const kindLabel=type==="plane"?"Espejo plano":type==="concave"?"Espejo cóncavo":"Espejo convexo";
 if(type==="plane")return {type,kindLabel,di:-do_,m:1,atInfinity:false,real:false,virtual:true,imageType:"virtual, derecha e igual tamaño",description:`En un espejo plano la imagen es virtual, derecha y del mismo tamaño. Se forma ${do_.toFixed(1)} cm detrás del espejo, a la misma distancia que el objeto delante.`,f};
 const den=do_-f;
 if(Math.abs(den)<.35)return {type,kindLabel,di:Infinity,m:-Infinity,atInfinity:true,real:type==="concave",virtual:false,imageType:"imagen en el infinito",description:`El objeto está prácticamente en el foco (${v.focal} cm). Los rayos reflejados salen paralelos y la imagen se forma en el infinito; no existe una imagen nítida a distancia finita.`,f};
 const di=f*do_/den,m=-di/do_,real=di>0,virtual=di<0;
 let imageType=real?"real e invertida":"virtual y derecha";
 if(Math.abs(Math.abs(m)-1)<.08)imageType+=", tamaño similar";else imageType+=Math.abs(m)>1?", aumentada":", reducida";
 return {type,kindLabel,di,m,atInfinity:false,real,virtual,imageType,description:`${kindLabel}. La imagen es ${imageType}. La ecuación 1/f = 1/do + 1/di da di = ${di.toFixed(2)} cm; el aumento lateral es m = ${m.toFixed(2)}. ${real?"Al ser real, puede proyectarse sobre una pantalla.":"Al ser virtual, no puede proyectarse sobre una pantalla."}`,f};
}

// Simulators
const simData={
ohm:{title:"Ley de Ohm",desc:"Explora la relación entre voltaje, corriente y resistencia en un circuito eléctrico.",tag:"Electricidad",controls:[["volt","Voltaje (V)",1,24,12,.5],["res","Resistencia (Ω)",1,20,4,.5]],calc:v=>({value:(v.volt/v.res).toFixed(2),unit:"amperios (A)",explain:`Al aplicar ${v.volt} V a una resistencia de ${v.res} Ω, la corriente resultante es ${v.volt} / ${v.res}.`,visual:"⚡ Fuente de voltaje  ───── Resistencia"})},
field:{title:"Campo magnético",desc:"Observa cómo cambia la fuerza magnética sobre una carga en movimiento.",tag:"Electromagnetismo",controls:[["charge","Carga (µC)",1,10,2,.5],["speed","Velocidad (m/s)",1,20,10,1],["mag","Campo magnético (T)",.1,2,.5,.1],["angle","Ángulo (°)",0,90,90,5]],calc:v=>({value:(v.charge*1e-6*v.speed*v.mag*Math.sin(v.angle*Math.PI/180)).toExponential(3),unit:"newtons (N)",explain:"F = |q| · v · B · sen(θ). Se muestra la magnitud de la fuerza magnética; la dirección depende de los sentidos de v y B.",visual:"q  → v      × B"})},
faraday:{title:"Ley de Faraday",desc:"Modifica el número de espiras y la variación del flujo magnético para calcular la FEM inducida.",tag:"Inducción magnética",controls:[["turns","Número de espiras (N)",1,100,20,1],["delta","Cambio de flujo (Wb)",.01,2,.5,.01],["time","Intervalo de tiempo (s)",.1,5,1,.1]],calc:v=>({value:(-v.turns*v.delta/v.time).toFixed(3),unit:"voltios (V)",explain:"ε = −N · ΔΦ / Δt. El signo negativo expresa la ley de Lenz; el resultado conserva ese signo.",visual:"Bobina  )))))   ↗ Flujo magnético"})},
mirrors:{title:"Reflexión y espejos",desc:"Investiga espejos planos, cóncavos y convexos. Cambia el tipo de espejo, la distancia focal y la posición del objeto para descubrir dónde y cómo se forma la imagen.",tag:"Óptica geométrica",controls:[["distance","Distancia del objeto (cm)",5,100,30,1],["focal","Distancia focal (cm)",5,30,15,1],["height","Altura del objeto (cm)",1,12,5,.5]],calc:v=>{const m=mirrorPhysics(v);return {value:m.atInfinity?"En el infinito":`${m.di.toFixed(2)} cm`,unit:m.atInfinity?"imagen no se forma a distancia finita":"distancia de imagen (con signo)",explain:m.description,visual:m.kindLabel+" · "+m.imageType};}},
coulomb:{title:"Ley de Coulomb",desc:"Explora la fuerza eléctrica entre dos cargas puntuales según su valor y separación.",tag:"Electricidad",controls:[["q1","Carga 1 (µC)",-20,20,4,.5],["q2","Carga 2 (µC)",-20,20,6,.5],["dist","Separación (cm)",1,50,10,1]],calc:v=>({value:(8.98755e9*Math.abs(v.q1*v.q2)*1e-12/(v.dist/100)**2).toExponential(3),unit:"newtons (N)",explain:"F = k·|q₁q₂|/r². La fuerza aumenta con las cargas y disminuye con el cuadrado de la distancia.",visual:"(+q₁)  ← fuerza →  (+q₂)"})},
electric:{title:"Campo eléctrico",desc:"Observa cómo la intensidad del campo cambia con la carga y la distancia.",tag:"Electricidad",controls:[["charge","Carga fuente (µC)",1,20,5,.5],["dist","Distancia (cm)",1,100,20,1]],calc:v=>({value:(8.98755e9*v.charge*1e-6/(v.dist/100)**2).toExponential(3),unit:"N/C",explain:"E = k·|Q|/r². Al alejarse de la carga, el campo disminuye rápidamente.",visual:"Carga Q  •──────→ Punto de evaluación"})},
gauss:{title:"Ley de Gauss",desc:"Calcula el flujo eléctrico a través de una superficie cerrada a partir de la carga encerrada.",tag:"Electricidad",controls:[["charge","Carga encerrada (µC)",.1,20,2,.1]],calc:v=>({value:(gaussEnclosed(v)*1e-6/8.8541878128e-12).toExponential(3),unit:"N·m²/C",explain:gaussEnclosed(v)===0?"La carga está fuera de la superficie cerrada. La carga neta encerrada es cero y, por la ley de Gauss, el flujo neto también es cero.":"ΦE = Qenc/ε₀. El flujo neto depende de la carga encerrada, no de la forma ni del tamaño de la superficie.",visual:`Superficie ${v.surfaceShape||"esférica"} · carga ${v.chargePosition==="outside"?"exterior":"interior"}`})},
potential:{title:"Potencial eléctrico",desc:"Calcula el potencial creado por una carga puntual a cierta distancia.",tag:"Electricidad",controls:[["charge","Carga (µC)",-20,20,5,.5],["dist","Distancia (cm)",1,100,20,1]],calc:v=>({value:(8.98755e9*v.charge*1e-6/(v.dist/100)).toFixed(2),unit:"voltios (V)",explain:"V = k·Q/r. El signo del potencial depende del signo de la carga fuente.",visual:"Carga puntual Q  •──── Punto a distancia r"})},
ampere:{title:"Ley de Ampère",desc:"Explora el campo magnético alrededor de un conductor recto recorrido por corriente.",tag:"Magnetismo",controls:[["current","Corriente (A)",1,20,5,.5],["dist","Distancia al cable (cm)",1,30,5,1]],calc:v=>({value:(2e-7*v.current/(v.dist/100)).toExponential(3),unit:"teslas (T)",explain:"B = μ₀I/(2πr). El campo aumenta con la corriente y disminuye al alejarse del cable.",visual:"Corriente ↑  │ cable │  líneas circulares de B"})},
series:{title:"Circuito en serie",desc:"Cambia las resistencias y observa la resistencia equivalente del circuito.",tag:"Circuitos",controls:[["r1","Resistencia 1 (Ω)",1,100,10,1],["r2","Resistencia 2 (Ω)",1,100,20,1],["r3","Resistencia 3 (Ω)",1,100,30,1],["voltage","Voltaje de la batería (V)",1,24,12,1]],calc:v=>({value:(v.r1+v.r2+v.r3).toFixed(2),unit:"ohmios (resistencia equivalente)",explain:`Req = R₁ + R₂ + R₃ = ${(v.r1+v.r2+v.r3).toFixed(1)} Ω. Con una fuente de ${v.voltage} V circula una corriente común de ${(v.voltage/(v.r1+v.r2+v.r3)).toFixed(3)} A; las caídas de tensión se reparten proporcionalmente a cada resistencia.`,visual:"Batería ─ R₁ ─ R₂ ─ R₃ ─ retorno"})},
waves:{title:"Ondas electromagnéticas",desc:"Relaciona frecuencia y longitud de onda usando la velocidad de la luz.",tag:"Ondas",controls:[["freq","Frecuencia (MHz)",1,1000,100,1]],calc:v=>{const med=waveMedium(v),lambda=med.speed/(v.freq*1e6);return {value:lambda.toFixed(3),unit:"metros (longitud de onda)",explain:`En ${med.label.toLowerCase()}, la rapidez es v = c/n = ${(med.speed).toExponential(3)} m/s. Al pasar de medio, la frecuencia se mantiene y cambia la longitud de onda: λ = v/f.`,visual:`Medio: ${med.label} · índice n = ${med.n}`};}},
freefall:{title:"Caída libre",desc:"Simula la velocidad y la distancia recorrida por un objeto que cae desde el reposo.",tag:"Mecánica",controls:[["time","Tiempo (s)",.1,5,2,.1],["gravity","Gravedad (m/s²)",1,15,9.81,.1],["initial","Velocidad inicial hacia abajo (m/s)",-10,20,0,1]],calc:v=>({value:(v.initial*v.time+.5*v.gravity*v.time*v.time).toFixed(2),unit:"metros de desplazamiento vertical",explain:`y = v₀t + ½gt². La velocidad en ese instante es ${(v.initial+v.gravity*v.time).toFixed(2)} m/s. Un valor inicial negativo representa un lanzamiento hacia arriba. Se desprecia la resistencia del aire.`,visual:`v₀ = ${v.initial} m/s · g = ${v.gravity} m/s²`})},
projectile:{title:"Tiro parabólico",desc:"Modifica la velocidad inicial y el ángulo para estimar el alcance horizontal.",tag:"Mecánica",controls:[["speed","Velocidad inicial (m/s)",1,50,20,1],["angle","Ángulo (°)",5,85,45,1],["height","Altura inicial (m)",0,30,0,1],["gravity","Gravedad (m/s²)",1,15,9.81,.1]],calc:v=>{const a=v.angle*Math.PI/180,vy=v.speed*Math.sin(a),vx=v.speed*Math.cos(a),t=(vy+Math.sqrt(vy*vy+2*v.gravity*v.height))/v.gravity,R=vx*t,H=v.height+vy*vy/(2*v.gravity);return {value:R.toFixed(2),unit:"metros (alcance horizontal)",explain:`Como el lanzamiento puede partir desde una altura h₀, el tiempo de vuelo se obtiene de h₀ + v₀ sen(θ)t − ½gt² = 0. Tiempo de vuelo: ${t.toFixed(2)} s. Altura máxima sobre el suelo: ${H.toFixed(2)} m.`,visual:`v₀ = ${v.speed} m/s · θ = ${v.angle}° · h₀ = ${v.height} m`};}},
mru:{title:"Movimiento rectilíneo uniforme (MRU)",desc:"Calcula el desplazamiento de un móvil que mantiene velocidad constante.",tag:"Mecánica",controls:[["speed","Velocidad (m/s)",0,40,10,1],["time","Tiempo (s)",1,60,5,1]],calc:v=>({value:(v.speed*v.time).toFixed(2),unit:"metros de desplazamiento",explain:"Δx = v·t. En MRU la velocidad es constante y la aceleración es cero.",visual:"● ─────────→ movimiento en línea recta"})},
mruv:{title:"Movimiento rectilíneo uniformemente variado (MRUV)",desc:"Observa cómo cambia la velocidad con una aceleración constante.",tag:"Mecánica",controls:[["initial","Velocidad inicial (m/s)",0,30,5,1],["accel","Aceleración (m/s²)",-5,10,2,.5],["time","Tiempo (s)",1,20,4,1]],calc:v=>({value:(v.initial+v.accel*v.time).toFixed(2),unit:"m/s (velocidad final)",explain:"v = v₀ + at. La aceleración constante modifica la velocidad de manera uniforme.",visual:`v₀ = ${v.initial} m/s  →  a = ${v.accel} m/s²`})},
work:{title:"Trabajo y energía",desc:"Calcula el trabajo realizado por una fuerza y el cambio de energía asociado.",tag:"Mecánica",controls:[["force","Fuerza (N)",1,100,20,1],["distance","Desplazamiento (m)",.1,20,5,.1],["angle","Ángulo fuerza-desplazamiento (°)",0,180,0,1]],calc:v=>({value:(v.force*v.distance*Math.cos(v.angle*Math.PI/180)).toFixed(2),unit:"joules (J) de trabajo",explain:"W = F·d·cosθ. El trabajo es positivo si la fuerza favorece el desplazamiento y negativo si se opone.",visual:"F →   [objeto]  → d"})},
thermal:{title:"Dilatación térmica",desc:"Calcula cuánto cambia la longitud de una barra al variar su temperatura.",tag:"Térmica",controls:[["alpha","Coeficiente α (×10⁻⁶/°C)",1,30,12,1],["length","Longitud inicial (m)",.1,10,2,.1],["delta","Cambio de temperatura (°C)",-50,100,40,1]],calc:v=>({value:(v.alpha*1e-6*v.length*v.delta*1000).toFixed(4),unit:"milímetros de variación",explain:"ΔL = α·L₀·ΔT. Un ΔT positivo produce expansión y uno negativo produce contracción.",visual:"Barra  ━━━━━━━━━  →  barra dilatada"})},
calor:{title:"Calorimetría",desc:"Calcula el calor absorbido o cedido según la masa, el calor específico y el cambio térmico.",tag:"Térmica",controls:[["mass","Masa (kg)",.1,10,2,.1],["specific","Calor específico (J/kg·°C)",100,5000,4186,10],["delta","Cambio de temperatura (°C)",-50,100,20,1]],calc:v=>({value:(v.mass*v.specific*v.delta).toFixed(2),unit:"joules (J)",explain:"Q = m·c·ΔT. El signo indica si el cuerpo absorbe calor (positivo) o lo cede (negativo).",visual:"🔥  calor →  [sustancia]  ΔT"})}
};
const simGraphSpecs={
  ohm:{x:"volt",xLabel:"Voltaje (V)",yLabel:"Corriente (A)",fn:(v,x)=>x/v.res},
  field:{x:"angle",xLabel:"Ángulo (°)",yLabel:"Fuerza magnética (N)",fn:(v,x)=>Math.abs(v.charge*1e-6*v.speed*v.mag*Math.sin(x*Math.PI/180))},
  faraday:{x:"delta",xLabel:"Cambio de flujo (Wb)",yLabel:"FEM inducida (V)",fn:(v,x)=>-v.turns*x/v.time},
  mirrors:{x:"distance",xLabel:"Distancia del objeto (cm)",yLabel:"Distancia de imagen (cm)",fn:(v,x)=>{const f=v.mirrorType==="concave"?v.focal:v.mirrorType==="convex"?-v.focal:Infinity;if(!Number.isFinite(f))return -x;const den=x-f;if(Math.abs(den)<.6)return 120*Math.sign(f||1);return Math.max(-120,Math.min(120,f*x/den));}},
  coulomb:{x:"dist",xLabel:"Separación (cm)",yLabel:"Fuerza eléctrica (N)",fn:(v,x)=>8.98755e9*Math.abs(v.q1*v.q2)*1e-12/(x/100)**2},
  electric:{x:"dist",xLabel:"Distancia (cm)",yLabel:"Campo eléctrico (N/C)",fn:(v,x)=>8.98755e9*v.charge*1e-6/(x/100)**2},
  gauss:{x:"charge",xLabel:"Carga encerrada (µC)",yLabel:"Flujo eléctrico (N·m²/C)",fn:(v,x)=>(v.chargePosition==='outside'?0:x*1e-6/8.8541878128e-12)},
  potential:{x:"dist",xLabel:"Distancia (cm)",yLabel:"Potencial (V)",fn:(v,x)=>8.98755e9*v.charge*1e-6/(x/100)},
  ampere:{x:"dist",xLabel:"Distancia al cable (cm)",yLabel:"Campo magnético (T)",fn:(v,x)=>2e-7*v.current/(x/100)},
  series:{x:"r1",xLabel:"Resistencia 1 (Ω)",yLabel:"Resistencia equivalente (Ω)",fn:(v,x)=>x+v.r2+v.r3},
  waves:{x:"freq",xLabel:"Frecuencia (MHz)",yLabel:"Longitud de onda (m)",fn:(v,x)=>waveMedium(v).speed/(x*1e6)},
  freefall:{x:"time",xLabel:"Tiempo (s)",yLabel:"Desplazamiento vertical (m)",fn:(v,x)=>v.initial*x+.5*v.gravity*x*x},
  projectile:{x:"range",xLabel:"Distancia horizontal (m)",yLabel:"Altura (m)",range:v=>{const a=v.angle*Math.PI/180,vy=v.speed*Math.sin(a),t=(vy+Math.sqrt(vy*vy+2*v.gravity*v.height))/v.gravity,R=v.speed*Math.cos(a)*t;return [0,Math.max(.1,R)];},marker:v=>{const a=v.angle*Math.PI/180,vy=v.speed*Math.sin(a),t=(vy+Math.sqrt(vy*vy+2*v.gravity*v.height))/v.gravity;return v.speed*Math.cos(a)*t;},fn:(v,x)=>{const theta=v.angle*Math.PI/180,vx=v.speed*Math.cos(theta),vy=v.speed*Math.sin(theta),t=(vy+Math.sqrt(vy*vy+2*v.gravity*v.height))/v.gravity;if(vx<=0)return v.height;const tx=x/vx;return Math.max(0,v.height+vy*tx-.5*v.gravity*tx*tx);}},
  mru:{x:"time",xLabel:"Tiempo (s)",yLabel:"Desplazamiento (m)",fn:(v,x)=>v.speed*x},
  mruv:{x:"time",xLabel:"Tiempo (s)",yLabel:"Velocidad (m/s)",fn:(v,x)=>v.initial+v.accel*x},
  work:{x:"distance",xLabel:"Desplazamiento (m)",yLabel:"Trabajo (J)",fn:(v,x)=>v.force*x*Math.cos(v.angle*Math.PI/180)},
  thermal:{x:"delta",xLabel:"Cambio de temperatura (°C)",yLabel:"Dilatación (mm)",fn:(v,x)=>v.alpha*1e-6*v.length*x*1000},
  calor:{x:"delta",xLabel:"Cambio de temperatura (°C)",yLabel:"Calor transferido (J)",fn:(v,x)=>v.mass*v.specific*x}
};
function makeSimGraph(key,vals){
  const spec=simGraphSpecs[key];
  const control=simData[key].controls.find(c=>c[0]===spec.x);
  const [xmin,xmax]=spec.range?spec.range(vals):[control[2],control[3]];
  const currentX=spec.marker?spec.marker(vals):vals[spec.x];
  const samples=56, raw=[];
  for(let i=0;i<=samples;i++){const x=xmin+(xmax-xmin)*i/samples;raw.push({x,y:spec.fn(vals,x)});}
  const ys=raw.map(p=>p.y).concat([spec.fn(vals,Math.max(xmin,Math.min(xmax,currentX)))]);
  let ymin=Math.min(...ys),ymax=Math.max(...ys);
  if(!Number.isFinite(ymin)||!Number.isFinite(ymax)){ymin=0;ymax=1;}
  if(Math.abs(ymax-ymin)<1e-12){const pad=Math.max(1,Math.abs(ymax)*.15);ymin-=pad;ymax+=pad;}else{const pad=(ymax-ymin)*.14;ymin-=pad;ymax+=pad;}
  const W=680,H=250,L=66,R=22,T=18,B=48, iw=W-L-R,ih=H-T-B;
  const X=x=>L+(x-xmin)/(xmax-xmin||1)*iw;
  const Y=y=>T+(ymax-y)/(ymax-ymin)*ih;
  const path=raw.map((p,i)=>`${i?'L':'M'}${X(p.x).toFixed(2)},${Y(p.y).toFixed(2)}`).join(' ');
  const mx=Math.max(xmin,Math.min(xmax,currentX)),my=spec.fn(vals,mx),px=X(mx),py=Y(my);
  const grid=Array.from({length:5},(_,i)=>{const y=T+i*ih/4,val=ymax-i*(ymax-ymin)/4;return `<line x1="${L}" y1="${y}" x2="${W-R}" y2="${y}" class="graph-gridline"/><text x="${L-10}" y="${y+4}" text-anchor="end" class="graph-tick">${formatGraphNumber(val)}</text>`;}).join('');
  const xTicks=Array.from({length:5},(_,i)=>{const x=L+i*iw/4,val=xmin+i*(xmax-xmin)/4;return `<text x="${x}" y="${H-25}" text-anchor="middle" class="graph-tick">${formatGraphNumber(val)}</text>`;}).join('');
  return `<div class="sim-graph-card"><div class="graph-heading"><div><span class="result-label">GRÁFICO EN TIEMPO REAL</span><h3>${spec.yLabel} según ${spec.xLabel.toLowerCase()}</h3></div><span class="graph-live"><i></i> Actualizado</span></div><div class="graph-canvas"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Gráfico de ${spec.yLabel} en función de ${spec.xLabel}">${grid}<line x1="${L}" y1="${T+ih}" x2="${W-R}" y2="${T+ih}" class="graph-axis"/><line x1="${L}" y1="${T}" x2="${L}" y2="${T+ih}" class="graph-axis"/>${xTicks}<path d="${path}" class="graph-curve"/><line x1="${px}" y1="${T}" x2="${px}" y2="${T+ih}" class="graph-marker-line"/><circle cx="${px}" cy="${py}" r="6" class="graph-marker"/><circle cx="${px}" cy="${py}" r="11" class="graph-marker-halo"/><text x="${Math.min(W-R-4,Math.max(L+4,px))}" y="${Math.max(T+12,py-13)}" text-anchor="middle" class="graph-point-label">(${formatGraphNumber(mx)}, ${formatGraphNumber(my)})</text><text x="${L+iw/2}" y="${H-4}" text-anchor="middle" class="graph-axis-label">${spec.xLabel}</text></svg></div><div class="graph-reading"><span>Valor seleccionado</span><strong>${formatGraphNumber(mx)} ${graphUnitFor(key,spec.x)}</strong><span class="graph-reading-separator">→</span><span>Resultado</span><strong>${formatGraphNumber(my)} ${graphUnitFor(key,'y')}</strong></div><p class="graph-hint">Mueve los controles para observar cómo cambia la curva y cómo se desplaza el punto de referencia.</p></div>`;
}
function formatGraphNumber(n){if(!Number.isFinite(n))return '—';const a=Math.abs(n);if(a!==0&&(a>=10000||a<.001))return n.toExponential(2);return Number(n.toFixed(3)).toString();}
function graphUnitFor(key,axis){const xUnits={dist:'cm',time:'s',angle:'°',volt:'V',delta:key==='faraday'?'Wb':'°C',charge:'µC',r1:'Ω',freq:'MHz',range:'m',distance:'m'};const yUnits={ohm:'A',field:'N',faraday:'V',mirrors:'°',coulomb:'N',electric:'N/C',gauss:'N·m²/C',potential:'V',ampere:'T',series:'Ω',waves:'m',freefall:'m',projectile:'m',mru:'m',mruv:'m/s',work:'J',thermal:'mm',calor:'J'};return axis==='y'?yUnits[key]||'':xUnits[axis]||'';}

function simSceneSvg(key,v){
 const text=(x,y,t,size=13,fill='#656b82',anchor='middle')=>`<text x="${x}" y="${y}" font-size="${size}" fill="${fill}" text-anchor="${anchor}" font-family="Inter,Arial,sans-serif">${t}</text>`;
 const line=(x1,y1,x2,y2,color='#8c82df',w=3,dash='')=>`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${color}" stroke-width="${w}" ${dash?`stroke-dasharray="${dash}"`:''} stroke-linecap="round"/>`;
 const ball=(x,y,r,fill,label)=>`<circle cx="${x}" cy="${y}" r="${r}" fill="${fill}" stroke="#fff" stroke-width="3"/><text x="${x}" y="${y+5}" fill="#fff" font-size="${Math.max(11,r*.75)}" font-weight="800" text-anchor="middle">${label}</text>`;
 let body='';
 switch(key){
 case 'coulomb':{const gap=130+Math.min(180,v.dist*3);const x1=380-gap/2,x2=380+gap/2;const same=Math.sign(v.q1)===Math.sign(v.q2);body=`${line(80,150,680,150,'#d9dbea',2)}${ball(x1,150,Math.min(34,18+Math.abs(v.q1)),v.q1>=0?'#e58b75':'#658de0',v.q1>=0?'+':'−')}<g id="dragCharge" style="cursor:ew-resize">${ball(x2,150,Math.min(34,18+Math.abs(v.q2)),v.q2>=0?'#e58b75':'#658de0',v.q2>=0?'+':'−')}</g>${line(x1+40,150,x1+(same?-75:75),150,'#d78b67',4)}${line(x2-40,150,x2+(same?75:-75),150,'#d78b67',4)}${text(x1,205,`q₁ = ${v.q1} µC`)}${text(x2,205,`q₂ = ${v.q2} µC`)}${text(380,65,same?'Cargas del mismo signo: se repelen':'Cargas de signo opuesto: se atraen',16,'#554a9b')}${text(380,245,`Separación: ${v.dist} cm · Las flechas indican el sentido de la interacción`,12)}`;break;}
 case 'electric':{const cx=210,cy=150,r=24+Math.min(55,v.charge*2);body=`${Array.from({length:12},(_,i)=>{const a=i*Math.PI/6;return `<path d="M ${cx+Math.cos(a)*r} ${cy+Math.sin(a)*r} Q ${cx+Math.cos(a)*120} ${cy+Math.sin(a)*120} ${cx+Math.cos(a)*270} ${cy+Math.sin(a)*270}" fill="none" stroke="#8d83dc" stroke-width="2" opacity=".55"/>`}).join('')}${ball(cx,cy,r,'#e58b75','+')}${line(245,150,Math.min(650,245+v.dist*3.2),150,'#e0a16d',3,'5 5')}<g id="dragProbe" style="cursor:grab">${ball(Math.min(650,245+v.dist*3.2),150,12,'#5c9bc8','+q')}</g>${text(430,70,'Líneas de campo eléctrico',16,'#554a9b')}${text(430,230,`Punto de prueba a ${v.dist} cm`,12)}`;break;}
 case 'gauss':{const shape=v.surfaceShape||'sphere',inside=v.chargePosition!=='outside';const shell=shape==='cube'?'<rect x="225" y="65" width="310" height="175" rx="5" fill="#e8e5ff" fill-opacity=".22" stroke="#8578db" stroke-width="3"/>':shape==='cylinder'?'<path d="M230 85 C230 55 530 55 530 85 V215 C530 245 230 245 230 215 Z" fill="#e8e5ff" fill-opacity=".25" stroke="#8578db" stroke-width="3"/><ellipse cx="380" cy="85" rx="150" ry="30" fill="none" stroke="#aaa1eb" stroke-width="2"/>':'<ellipse cx="380" cy="150" rx="190" ry="105" fill="#e8e5ff" fill-opacity=".3" stroke="#8578db" stroke-width="3"/><ellipse cx="380" cy="150" rx="190" ry="105" fill="none" stroke="#aaa1eb" stroke-dasharray="5 6" stroke-width="2"/>';const qx=inside?380:620,qy=150;body=`${shell}${ball(qx,qy,inside?15:13,'#e58b75','+')}${Array.from({length:inside?8:0},(_,i)=>`<path d="M ${380+Math.cos(i*Math.PI/4)*25} ${150+Math.sin(i*Math.PI/4)*25} L ${380+Math.cos(i*Math.PI/4)*78} ${150+Math.sin(i*Math.PI/4)*78}" stroke="#d99a68" stroke-width="2"/>`).join('')}${text(380,30,`Superficie gaussiana: ${shape==='cube'?'cúbica':shape==='cylinder'?'cilíndrica':'esférica'}`,16,'#554a9b')}${text(380,280,inside?`Qenc = ${v.charge} µC · carga dentro de la superficie`:'La carga está fuera: Qenc = 0',13)}`;break;}
 case 'potential':{const cx=380,cy=150;body=`${[35,70,105,140,175].map((r,i)=>`<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#887cdb" stroke-width="2" opacity="${.9-i*.13}"/>`).join('')}${ball(cx,cy,23,v.charge>=0?'#e58b75':'#658de0',v.charge>=0?'+':'−')}${line(405,150,Math.min(650,405+v.dist*2),150,'#e0a16d',3,'5 5')}<g id="dragProbe" style="cursor:grab">${ball(Math.min(650,405+v.dist*2),150,9,'#5c9bc8','P')}</g>${text(380,35,'Superficies equipotenciales',16,'#554a9b')}${text(380,275,`Distancia de evaluación: ${v.dist} cm`,13)}`;break;}
 case 'ohm':{body=`<path d="M120 150 H230 l18 -24 28 48 28 -48 28 48 28 -48 18 24 H640 V215 H120 Z" fill="none" stroke="#887cdb" stroke-width="4" stroke-linejoin="round"/><rect x="75" y="115" width="45" height="70" rx="7" fill="#f0efff" stroke="#887cdb" stroke-width="3"/><path d="M96 125 V175 M108 138 V162" stroke="#887cdb" stroke-width="3"/>${text(97,205,'Batería',12)}${text(380,90,`R = ${v.res} Ω`,15,'#554a9b')}${text(380,260,`V = ${v.volt} V  ·  I = ${(v.volt/v.res).toFixed(2)} A`,14)}<circle class="sim-electron" cx="160" cy="150" r="6" fill="#e5a34d"/>`;break;}
 case 'field':{body=`${Array.from({length:7},(_,i)=>`<circle cx="380" cy="150" r="${30+i*24}" fill="none" stroke="#9b91df" stroke-dasharray="3 8" opacity=".7"/>`).join('')}${Array.from({length:9},(_,i)=>`<circle cx="${170+i*52}" cy="${65+(i%2)*170}" r="5" fill="#5b8cc9"/>`).join('')}${ball(380,150,20,'#e58b75','q')}${line(405,150,535,150,'#e0a16d',4)}${text(570,155,'v',14,'#b47a40')}${line(380,125,380,55,'#58a88b',4)}${text(400,50,'F',15,'#398c70')}${text(380,285,`θ = ${v.angle}° · B = ${v.mag} T · v = ${v.speed} m/s`,13)}`;break;}
 case 'ampere':{body=`<rect x="370" y="35" width="20" height="230" rx="9" fill="#d5d8e5" stroke="#7b8195" stroke-width="2"/><path d="M380 220 V75" stroke="#d98b63" stroke-width="5"/><path d="M369 90 L380 70 L391 90" fill="none" stroke="#d98b63" stroke-width="4"/>${[45,80,115,150].map((r)=>`<ellipse cx="380" cy="150" rx="${r*1.55}" ry="${r*.7}" fill="none" stroke="#8277d6" stroke-width="2" opacity=".7"/>`).join('')}${text(380,25,'Líneas circulares del campo magnético',15,'#554a9b')}${text(380,285,`I = ${v.current} A · r = ${v.dist} cm`,13)}`;break;}
 case 'faraday':{body=`<rect x="130" y="105" width="90" height="90" rx="8" fill="#e58b75" opacity=".9"/><rect x="220" y="105" width="90" height="90" rx="8" fill="#658de0" opacity=".9"/>${text(175,155,'N',28,'#fff')}${text(265,155,'S',28,'#fff')}${Array.from({length:7},(_,i)=>`<path d="M 315 ${112+i*13} C 365 ${80+i*13} 420 ${80+i*13} 465 ${112+i*13}" fill="none" stroke="#9b91df" stroke-width="2"/>`).join('')}<rect x="455" y="85" width="24" height="130" rx="8" fill="none" stroke="#887cdb" stroke-width="5"/><path d="M480 150 H575" stroke="#e0a16d" stroke-width="3"/><circle class="sim-pulse" cx="575" cy="150" r="13" fill="#e5a34d"/>${text(465,55,`${v.turns} espiras`,14,'#554a9b')}${text(380,270,`Variación de flujo: ${v.delta} Wb en ${v.time} s`,13)}`;break;}
 case 'series':{const R=v.r1+v.r2+v.r3,I=v.voltage/R;body=`<path d="M90 150 H170 M250 150 H300 M380 150 H430 M510 150 H660 V220 H90 V150" fill="none" stroke="#887cdb" stroke-width="4"/><rect x="170" y="125" width="80" height="50" rx="7" fill="#f0efff" stroke="#887cdb" stroke-width="3"/><rect x="300" y="125" width="80" height="50" rx="7" fill="#f0efff" stroke="#887cdb" stroke-width="3"/><rect x="430" y="125" width="80" height="50" rx="7" fill="#f0efff" stroke="#887cdb" stroke-width="3"/>${text(210,155,`${v.r1} Ω`,13,'#554a9b')}${text(340,155,`${v.r2} Ω`,13,'#554a9b')}${text(470,155,`${v.r3} Ω`,13,'#554a9b')}${text(105,130,`${v.voltage} V`,12,'#b47a40')}${text(380,65,'La corriente es igual en todos los elementos',15,'#554a9b')}${text(380,270,`I = ${I.toFixed(3)} A · Req = ${R.toFixed(1)} Ω · ΔV₁ = ${(I*v.r1).toFixed(1)} V`,13)}`;break;}
 case 'waves':{const med=waveMedium(v),lambda=Math.max(22,Math.min(180,med.speed/(v.freq*1e6)*85));let pts=[];for(let x=55;x<=705;x+=5)pts.push(`${x},${150-55*Math.sin((x-55)*2*Math.PI/lambda)}`);body=`<path d="M ${pts.join(' L ')}" fill="none" stroke="#8175d7" stroke-width="4" stroke-linecap="round"/>${line(55,150,705,150,'#d8d9e5',1)}${line(90,75,90,225,'#d8d9e5',1)}${line(90,95,90+lambda,95,'#e0a16d',3)}${line(90,88,90,102,'#e0a16d',2)}${line(90+lambda,88,90+lambda,102,'#e0a16d',2)}${text(90+lambda/2,80,`λ = ${(med.speed/(v.freq*1e6)).toFixed(3)} m`,13,'#b47a40')}${text(380,270,`Frecuencia: ${v.freq} MHz · medio: ${med.label} · rapidez: ${med.speed.toExponential(2)} m/s`,13)}`;break;}
 case 'mirrors':{const m=mirrorPhysics(v),mx=520,axis=160,scale=3.65,ox=Math.max(90,Math.min(450,mx-v.distance*scale)),fx=Number.isFinite(m.f)?mx-m.f*scale:mx-150,cx=Number.isFinite(m.f)?mx-2*m.f*scale:mx-300;const oh=Math.max(18,Math.min(52,v.height*4.2)),ih=m.atInfinity?0:Math.max(8,Math.min(105,oh*Math.abs(m.m)))*(m.m<0?-1:1),ix=m.atInfinity?mx-360:mx-m.di*scale;const mirrorPath=m.type==='plane'?`M ${mx} 38 V 280`:m.type==='concave'?`M ${mx-35} 38 Q ${mx+35} 160 ${mx-35} 280`:`M ${mx+35} 38 Q ${mx-35} 160 ${mx+35} 280`;const ray1Y=axis-oh;let rays='';if(!m.atInfinity){const topX=ox,topY=ray1Y;const rayColor='#df985d';if(m.real){rays=`<path d="M ${topX} ${topY} L ${mx} ${topY} L ${ix} ${axis-ih}" fill="none" stroke="${rayColor}" stroke-width="2.5"/><path d="M ${topX} ${topY} L ${mx} ${axis+(topY-axis)*.18} L ${ix} ${axis-ih}" fill="none" stroke="#70a4cb" stroke-width="2.2"/>`;}else{const leftEnd=90,virtualY=axis-ih,slope=(virtualY-topY)/(ix-mx||1),outY=topY+(leftEnd-mx)*slope;rays=`<path d="M ${topX} ${topY} L ${mx} ${topY} L ${leftEnd} ${outY}" fill="none" stroke="${rayColor}" stroke-width="2.5"/><path d="M ${mx} ${topY} L ${ix} ${virtualY}" fill="none" stroke="#70a4cb" stroke-width="2.2" stroke-dasharray="6 5"/>`;}}const imageArrow=m.atInfinity?'':`<line x1="${ix}" y1="${axis}" x2="${ix}" y2="${axis-ih}" stroke="${m.real?'#d98c63':'#5b9ac4'}" stroke-width="5"/><path d="M ${ix-7} ${axis-ih+10} L ${ix} ${axis-ih} L ${ix+7} ${axis-ih+10}" fill="none" stroke="${m.real?'#d98c63':'#5b9ac4'}" stroke-width="3"/>`;body=`${line(45,axis,710,axis,'#9da2b5',1,'5 5')}${line(fx,axis-5,fx,axis+5,'#8b7bd8',2)}${text(fx,axis+20,'F',12,'#695bb8')}${m.type!=='plane'?`${line(cx,axis-5,cx,axis+5,'#8b7bd8',2)}${text(cx,axis+20,'C',12,'#695bb8')}`:''}<path d="${mirrorPath}" fill="none" stroke="#8a8fa4" stroke-width="9" stroke-linecap="round"/><path d="${mirrorPath}" fill="none" stroke="#dce0eb" stroke-width="3" stroke-linecap="round"/>${rays}<g id="dragMirrorObject" style="cursor:ew-resize;touch-action:none"><line x1="${ox}" y1="${axis}" x2="${ox}" y2="${axis-oh}" stroke="#e3a05f" stroke-width="5"/><path d="M ${ox-8} ${axis-oh+12} L ${ox} ${axis-oh} L ${ox+8} ${axis-oh+12}" fill="none" stroke="#e3a05f" stroke-width="3"/></g>${imageArrow}${text(ox,axis+23,'Objeto',12,'#b47a40')}${m.atInfinity?'':text(Math.max(55,Math.min(700,ix)),m.m<0?axis+25:axis+25,'Imagen',12,m.real?'#b47a40':'#4d8fb7')}${text(380,25,m.kindLabel,16,'#554a9b')}${text(380,292,m.atInfinity?'Objeto en el foco: rayos reflejados paralelos':`do = ${v.distance} cm · f = ${v.focal} cm · di = ${m.di.toFixed(1)} cm · m = ${m.m.toFixed(2)}`,12)}`;break;}
 case 'freefall':{const displacement=v.initial*v.time+.5*v.gravity*v.time*v.time;const y=Math.max(42,Math.min(220,55+displacement*4));body=`${line(380,25,380,250,'#d4d6e1',2,'5 7')}${line(260,250,500,250,'#9297aa',3)}<circle class="sim-fall-ball" cx="380" cy="${y}" r="19" fill="#e5a34d" stroke="#fff" stroke-width="3"/><path d="M380 ${y+27} V${Math.min(245,y+80)} M369 ${Math.min(235,y+68)} L380 ${Math.min(248,y+82)} L391 ${Math.min(235,y+68)}" fill="none" stroke="#7c70d0" stroke-width="3"/>${text(380,25,'Caída desde el reposo',15,'#554a9b')}${text(380,285,`t = ${v.time} s · v₀ = ${v.initial} m/s · g = ${v.gravity} m/s²`,13)}`;break;}
 case 'projectile':{const a=v.angle*Math.PI/180,vx=v.speed*Math.cos(a),vy=v.speed*Math.sin(a),tFlight=(vy+Math.sqrt(vy*vy+2*v.gravity*v.height))/v.gravity,R=vx*tFlight,H=v.height+vy*vy/(2*v.gravity),scale=Math.min(5.2,560/Math.max(1,R)),ground=245;let path=[];for(let i=0;i<=70;i++){const t=tFlight*i/70,x=vx*t,y=v.height+vy*t-.5*v.gravity*t*t;path.push(`${90+x*scale},${ground-y*scale}`)}body=`${line(70,ground,700,ground,'#9297aa',3)}${line(90,ground,90,Math.max(35,ground-v.height*scale),'#c8c9d5',1,'4 5')}<path d="M ${path.join(' L ')}" fill="none" stroke="#8175d7" stroke-width="4" stroke-linecap="round"/>${line(90,ground-v.height*scale,90+Math.cos(a)*Math.min(110,v.speed*4),ground-v.height*scale-Math.sin(a)*Math.min(110,v.speed*4),'#e0a16d',4)}<g id="dragProjectile" style="cursor:grab">${ball(90+Math.cos(a)*Math.min(110,v.speed*4),ground-v.height*scale-Math.sin(a)*Math.min(110,v.speed*4),10,'#e5a34d','↗')}</g>${ball(90,ground-v.height*scale,7,'#e5a34d','')}${text(380,28,`Altura máxima: ${H.toFixed(1)} m`,15,'#554a9b')}${text(380,282,`v₀ = ${v.speed} m/s · θ = ${v.angle}° · alcance = ${R.toFixed(1)} m · h₀ = ${v.height} m`,12)}`;break;}
 case 'mru':{const x=130+Math.min(470,v.speed*v.time*1.2);body=`${line(80,210,690,210,'#aeb2c2',4)}${[120,240,360,480,600].map(x=>line(x,202,x,218,'#aeb2c2',2)).join('')}<rect class="sim-cart-body" x="${Math.min(650,x)}" y="155" width="54" height="35" rx="8" fill="#8175d7"/><circle cx="${Math.min(660,x+12)}" cy="194" r="7" fill="#4f5367"/><circle cx="${Math.min(692,x+42)}" cy="194" r="7" fill="#4f5367"/>${line(130,135,Math.min(620,x+25),135,'#e0a16d',3)}${text(380,80,'Velocidad constante',16,'#554a9b')}${text(380,270,`v = ${v.speed} m/s · t = ${v.time} s · Δx = ${(v.speed*v.time).toFixed(1)} m`,13)}`;break;}
 case 'mruv':{const vel=v.initial+v.accel*v.time;const x=130+Math.max(0,Math.min(480,(vel+20)*9));body=`${line(80,210,690,210,'#aeb2c2',4)}<rect x="${x}" y="155" width="62" height="36" rx="8" fill="#8175d7"/><circle cx="${x+13}" cy="195" r="7" fill="#4f5367"/><circle cx="${x+49}" cy="195" r="7" fill="#4f5367"}${line(x+30,140,x+30+Math.max(-80,Math.min(150,vel*4)),140,'#e0a16d',4)}${text(380,65,`Velocidad actual: ${vel.toFixed(2)} m/s`,16,'#554a9b')}${text(380,270,`a = ${v.accel} m/s² · t = ${v.time} s`,13)}`;break;}
 case 'work':{const a=v.angle*Math.PI/180;body=`${line(100,220,660,220,'#aeb2c2',4)}<rect x="330" y="150" width="100" height="65" rx="10" fill="#8175d7"/><text x="380" y="190" text-anchor="middle" fill="#fff" font-size="16" font-weight="800">m</text>${line(380,150,380+140*Math.cos(a),150-140*Math.sin(a),'#e0a16d',5)}${text(535,65,`F = ${v.force} N`,15,'#b47a40')}${text(380,270,`Desplazamiento: ${v.distance} m · ángulo: ${v.angle}°`,13)}`;break;}
 case 'thermal':{const width=Math.max(120,Math.min(480,300+v.alpha*v.length*v.delta*.045));body=`<rect x="${380-width/2}" y="125" width="${width}" height="50" rx="8" fill="#e6a46b" opacity=".85"/><path d="M ${380-width/2} 150 H ${380+width/2}" stroke="#b77743" stroke-width="3"/>${line(380-width/2,105,380-width/2,195,'#8175d7',2)}${line(380+width/2,105,380+width/2,195,'#8175d7',2)}${text(380,65,v.delta>=0?'La barra se expande al calentarse':'La barra se contrae al enfriarse',16,'#554a9b')}${text(380,245,`α = ${v.alpha} × 10⁻⁶ /°C · L₀ = ${v.length} m`,13)}${text(380,275,`Cambio de temperatura: ${v.delta} °C`,12)}`;break;}
 case 'calor':{const hot=Math.max(0,Math.min(1,(v.delta+50)/150));body=`<path d="M220 85 V220 Q220 250 250 250 H340 Q370 250 370 220 V85" fill="#f3f1fb" stroke="#9b91df" stroke-width="4"/><path d="M225 ${220-hot*115} H365 V220 Q365 245 340 245 H250 Q225 245 225 220" fill="#e8a46c" opacity=".85"/><path d="M430 85 V220 Q430 250 460 250 H550 Q580 250 580 220 V85" fill="#f3f1fb" stroke="#9b91df" stroke-width="4"/><path d="M435 ${220-hot*115} H575 V220 Q575 245 550 245 H460 Q435 245 435 220" fill="#7eb6d1" opacity=".85"/>${text(295,60,'Sistema térmico',14,'#554a9b')}${text(505,60,'Cambio de temperatura',14,'#554a9b')}${text(400,280,`m = ${v.mass} kg · c = ${v.specific} J/(kg·°C) · ΔT = ${v.delta} °C`,12)}`;break;}
 }
 return `<svg viewBox="0 0 760 300" role="img" aria-label="Modelo interactivo de ${simData[key].title}" xmlns="http://www.w3.org/2000/svg">${body}</svg>`;
}

function simMetrics(key,v){
 const mu0=4*Math.PI*1e-7,k=8.9875517923e9,g=9.81;
 const f={
  coulomb:()=>{const force=k*Math.abs(v.q1*v.q2)*1e-12/(v.dist/100)**2;return [['Fuerza eléctrica',force.toExponential(2),'N'],['Interacción',Math.sign(v.q1*v.q2)<0?'Atracción':'Repulsión',''],['Distancia',v.dist.toFixed(1),'cm'],['Producto de cargas',`${(v.q1*v.q2).toFixed(2)}`,'µC²']];},
  electric:()=>{const E=k*Math.abs(v.charge)*1e-6/(v.dist/100)**2;return [['Campo eléctrico',E.toExponential(2),'N/C'],['Potencial', (k*v.charge*1e-6/(v.dist/100)).toExponential(2),'V'],['Fuerza sobre 1 µC',(E*1e-6).toExponential(2),'N'],['Distancia',v.dist.toFixed(1),'cm']];},
  gauss:()=>[['Flujo eléctrico',(gaussEnclosed(v)*1e-6/8.8541878128e-12).toExponential(2),'N·m²/C'],['Carga encerrada',gaussEnclosed(v).toFixed(2),'µC'],['Superficie',v.surfaceShape||'sphere',''],['Carga',v.chargePosition==='outside'?'Exterior':'Interior','']],
  potential:()=>{const r=v.dist/100,Q=v.charge*1e-6;return [['Potencial eléctrico',(k*Q/r).toExponential(2),'V'],['Campo eléctrico',(k*Math.abs(Q)/(r*r)).toExponential(2),'N/C'],['Energía para 1 µC',(k*Q*1e-6/r).toExponential(2),'J'],['Distancia',v.dist.toFixed(1),'cm']];},
  ohm:()=>{const I=v.volt/v.res;return [['Corriente',I.toFixed(3),'A'],['Potencia disipada',(v.volt*I).toFixed(2),'W'],['Resistencia',v.res.toFixed(1),'Ω'],['Voltaje',v.volt.toFixed(1),'V']];},
  field:()=>{const F=Math.abs(v.charge)*1e-6*v.speed*v.mag*Math.sin(v.angle*Math.PI/180);return [['Fuerza magnética',F.toExponential(2),'N'],['Componente perpendicular',(v.speed*Math.sin(v.angle*Math.PI/180)).toFixed(2),'m/s'],['Ángulo',v.angle.toFixed(0),'°'],['Condición',v.angle===0?'Fuerza nula':v.angle===90?'Fuerza máxima':'Fuerza parcial','']];},
  faraday:()=>[['FEM inducida',(-v.turns*v.delta/v.time).toFixed(3),'V'],['Rapidez de cambio',(v.delta/v.time).toFixed(3),'Wb/s'],['Espiras',v.turns.toFixed(0),'N'],['Ley de Lenz','Se opone al cambio','']],
  ampere:()=>{const B=mu0*v.current/(2*Math.PI*(v.dist/100));return [['Campo magnético',B.toExponential(2),'T'],['Intensidad H',(v.current/(2*Math.PI*(v.dist/100))).toFixed(2),'A/m'],['Corriente',v.current.toFixed(1),'A'],['Distancia',v.dist.toFixed(1),'cm']];},
  series:()=>{const R=v.r1+v.r2+v.r3,I=v.voltage/R;return [['Resistencia equivalente',R.toFixed(2),'Ω'],['Corriente del circuito',I.toFixed(3),'A'],['Caída en R₁',(I*v.r1).toFixed(2),'V'],['Caída en R₂ + R₃',(I*(v.r2+v.r3)).toFixed(2),'V']];},
  waves:()=>{const hz=v.freq*1e6,med=waveMedium(v),lambda=med.speed/hz;return [['Longitud de onda',lambda.toFixed(3),'m'],['Período',(1/hz*1e9).toFixed(3),'ns'],['Frecuencia',v.freq.toFixed(1),'MHz'],['Rapidez',med.speed.toExponential(2),'m/s']];},
  mirrors:()=>{const m=mirrorPhysics(v);return [['Tipo de espejo',m.kindLabel,''],['Distancia imagen',m.atInfinity?'∞':m.di.toFixed(2),'cm'],['Aumento lateral',m.atInfinity?'—':m.m.toFixed(2),'×'],['Naturaleza',m.atInfinity?'En el infinito':m.real?'Real':'Virtual','']];},
  freefall:()=>[['Desplazamiento',(v.initial*v.time+.5*v.gravity*v.time*v.time).toFixed(2),'m'],['Velocidad final',(v.initial+v.gravity*v.time).toFixed(2),'m/s'],['Aceleración',v.gravity.toFixed(2),'m/s²'],['Velocidad inicial',v.initial.toFixed(1),'m/s']],
  projectile:()=>{const a=v.angle*Math.PI/180,vy=v.speed*Math.sin(a),vx=v.speed*Math.cos(a),t=(vy+Math.sqrt(vy*vy+2*v.gravity*v.height))/v.gravity;return [['Alcance',(vx*t).toFixed(2),'m'],['Altura máxima',(v.height+vy*vy/(2*v.gravity)).toFixed(2),'m'],['Tiempo de vuelo',t.toFixed(2),'s'],['Velocidad horizontal',vx.toFixed(2),'m/s']];},
  mru:()=>[['Desplazamiento',(v.speed*v.time).toFixed(2),'m'],['Velocidad',v.speed.toFixed(2),'m/s'],['Aceleración','0.00','m/s²'],['Tiempo',v.time.toFixed(1),'s']],
  mruv:()=>[['Velocidad final',(v.initial+v.accel*v.time).toFixed(2),'m/s'],['Desplazamiento',(v.initial*v.time+.5*v.accel*v.time**2).toFixed(2),'m'],['Aceleración',v.accel.toFixed(2),'m/s²'],['Cambio de velocidad',(v.accel*v.time).toFixed(2),'m/s']],
  work:()=>{const W=v.force*v.distance*Math.cos(v.angle*Math.PI/180);return [['Trabajo neto',W.toFixed(2),'J'],['Componente paralela',(v.force*Math.cos(v.angle*Math.PI/180)).toFixed(2),'N'],['Efecto',W>0?'Favorece el movimiento':W<0?'Se opone al movimiento':'No transfiere energía',''],['Energía transferida',Math.abs(W).toFixed(2),'J']];},
  thermal:()=>{const dl=v.alpha*1e-6*v.length*v.delta;return [['Variación de longitud',(dl*1000).toFixed(3),'mm'],['Longitud final',(v.length+dl).toFixed(5),'m'],['Cambio térmico',v.delta.toFixed(1),'°C'],['Comportamiento',dl>=0?'Expansión':'Contracción','']];},
  calor:()=>{const Q=v.mass*v.specific*v.delta;return [['Calor transferido',Q.toFixed(1),'J'],['Capacidad térmica',(v.mass*v.specific).toFixed(1),'J/°C'],['Cambio térmico',v.delta.toFixed(1),'°C'],['Proceso',Q>=0?'Absorbe calor':'Cede calor','']]}
 };
 return (f[key]||(()=>[]))();
}
function simInsight(key,v){
 const tips={coulomb:`Si duplicas la separación, la fuerza cae a la cuarta parte. Cambia el signo de una carga para pasar de repulsión a atracción.`,electric:`El campo de una carga puntual sigue una ley de inversa del cuadrado: al duplicar la distancia, queda en una cuarta parte.`,gauss:`El flujo neto depende de la carga encerrada, no de la forma ni del tamaño de la superficie gaussiana.`,potential:`El potencial es una magnitud escalar. Su signo depende del signo de la carga fuente; el campo eléctrico, en cambio, tiene dirección.`,ohm:`Con resistencia fija, la corriente crece proporcionalmente al voltaje. Con voltaje fijo, aumentar la resistencia reduce la corriente.`,field:`La fuerza magnética es máxima cuando la velocidad es perpendicular al campo y nula cuando ambos son paralelos.`,faraday:`Una variación de flujo más rápida o un mayor número de espiras produce una FEM inducida de mayor magnitud.`,ampere:`Al duplicar la corriente se duplica el campo. Al duplicar la distancia al cable, el campo se reduce a la mitad.`,series:`En serie la corriente es la misma en todos los elementos y el voltaje de la fuente se reparte entre las resistencias.`,waves:`En el vacío, frecuencia y longitud de onda son inversamente proporcionales: si la frecuencia aumenta, la longitud de onda disminuye.`,mirrors:`En un espejo plano, el ángulo de reflexión es igual al de incidencia y la imagen queda a la misma distancia detrás del espejo.`,freefall:`Sin resistencia del aire, todos los cuerpos tienen la misma aceleración gravitatoria local, independientemente de su masa.`,projectile:`El alcance depende de la rapidez inicial y del ángulo. Para una misma altura de salida y llegada, el alcance es máximo cerca de 45°.`,mru:`En MRU se recorren distancias iguales en tiempos iguales; la pendiente de la gráfica posición-tiempo representa la velocidad.`,mruv:`En MRUV la gráfica velocidad-tiempo es una recta y su pendiente representa la aceleración.`,work:`Una fuerza perpendicular al desplazamiento realiza trabajo nulo. Si apunta en sentido contrario, el trabajo es negativo.`,thermal:`La dilatación depende del material, de la longitud inicial y del cambio de temperatura. Un cambio negativo produce contracción.`,calor:`El calor transferido aumenta con la masa, el calor específico y la variación de temperatura. El signo indica el sentido de la transferencia.`};
 if(key==='mirrors'){const m=mirrorPhysics(v);return m.description+' Cambia entre cóncavo, convexo y plano; acerca el objeto al foco para observar el cambio de naturaleza y tamaño de la imagen.';}if(key==='gauss')return gaussEnclosed(v)===0?'Aunque existe una carga, está fuera de la superficie: su contribución al flujo neto encerrado es cero. Si la mueves al interior, el flujo cambia según Qenc/ε₀.':'La superficie encierra una carga neta. Cambiar su forma no cambia el flujo neto: lo determina únicamente la carga encerrada.';if(key==='waves')return 'Al pasar del vacío al agua o al vidrio, la frecuencia permanece constante en la frontera. La rapidez y la longitud de onda disminuyen cuando aumenta el índice de refracción.';return tips[key]||'Modifica una variable a la vez para identificar cómo afecta al fenómeno.';
}

let currentSim="coulomb";
function renderSim(key){currentSim=key;$$('[data-sim]').forEach(b=>b.classList.toggle('selected',b.dataset.sim===key));const d=simData[key];const c=$('#simulatorContent');c.innerHTML=`<div class="sim-head"><div><h2>${d.title}</h2><p>${d.desc}</p></div><span class="sim-tag">${d.tag}</span></div><div class="sim-lab"><div class="sim-lab-top"><div><span class="result-label">LABORATORIO VIRTUAL</span><h3>Experimenta con el fenómeno</h3><p>Modifica las variables y observa cómo responde el modelo físico.</p></div><div class="sim-lab-actions"><button type="button" class="sim-action" id="simReset">↺ Restablecer experimento</button></div></div>${key==="mirrors"?`<div class="sim-special-controls"><label for="mirrorType">Tipo de espejo</label><select id="mirrorType" class="sim-special-select"><option value="plane">Plano</option><option value="concave" selected>Cóncavo</option><option value="convex">Convexo</option></select><span>Convención: objeto delante del espejo; distancias en cm.</span></div>`:key==="gauss"?`<div class="sim-special-controls"><label for="gaussShape">Geometría de la superficie</label><select id="gaussShape" class="sim-special-select"><option value="sphere">Esfera</option><option value="cylinder">Cilindro cerrado</option><option value="cube">Cubo</option></select><label for="gaussPosition">Posición de la carga</label><select id="gaussPosition" class="sim-special-select"><option value="inside">Dentro</option><option value="outside">Fuera</option></select><span>La ley de Gauss relaciona el flujo neto con la carga encerrada.</span></div>`:key==="waves"?`<div class="sim-special-controls"><label for="waveMedium">Medio de propagación</label><select id="waveMedium" class="sim-special-select"><option value="vacuum">Vacío</option><option value="water">Agua</option><option value="glass">Vidrio</option></select><span>Al cambiar de medio, la frecuencia se conserva y cambia la rapidez y la longitud de onda.</span></div>`:""}<div class="sim-stage-tools"><label><input type="checkbox" id="simGrid" checked> Cuadrícula</label><label><input type="checkbox" id="simVectors" checked> Vectores y direcciones</label><label><input type="checkbox" id="simLabels" checked> Etiquetas</label></div><div class="sim-scene" id="simScene"></div><div class="sim-scene-caption" id="simSceneCaption">Laboratorio interactivo: modifica las variables y observa cómo responde el fenómeno físico.</div></div><div class="sim-body"><div class="controls"><div class="control-section-title">Variables del experimento</div>${d.controls.map(([id,label,min,max,val,step])=>`<div class="control-row"><label for="sim-${id}">${label}<output id="out-${id}">${val}</output></label><input id="sim-${id}" type="range" min="${min}" max="${max}" step="${step}" value="${val}"></div>`).join('')}</div><div class="sim-result"><span class="result-label">RESULTADO DEL SIMULADOR</span><div class="result-value" id="simResult">—</div><div class="result-unit" id="simUnit"></div><p class="result-explain" id="simExplain"></p><div class="sim-visual" id="simVisual"></div></div></div><div class="sim-dashboard"><div class="sim-dashboard-head"><div><span class="result-label">PANEL DE INSTRUMENTOS</span><h3>Mediciones en tiempo real</h3></div><span class="sim-live"><i></i> En vivo</span></div><div class="sim-metrics" id="simMetrics"></div><div class="sim-insight" id="simInsight"></div></div><div id="simGraph"></div>`;$('#simReset').addEventListener('click',()=>{d.controls.forEach(([id,,,,val])=>{$('#sim-'+id).value=val;});if(key==='mirrors')$('#mirrorType').value='concave';if(key==='gauss'){ $('#gaussShape').value='sphere';$('#gaussPosition').value='inside';}if(key==='waves')$('#waveMedium').value='vacuum';update();});function attachSceneDrag(){const svg=$('#simScene svg');if(!svg)return;const charge=svg.querySelector('#dragCharge');const bindDrag=(node,moveToValue)=>{if(!node)return;let startX=0,startY=0,dx=0,dy=0;node.addEventListener('pointerdown',e=>{e.preventDefault();node.setPointerCapture(e.pointerId);startX=e.clientX;startY=e.clientY;dx=0;dy=0;});node.addEventListener('pointermove',e=>{if(!node.hasPointerCapture(e.pointerId))return;const rect=svg.getBoundingClientRect();dx=(e.clientX-startX)*760/rect.width;dy=(e.clientY-startY)*300/rect.height;node.setAttribute('transform',`translate(${dx},${dy})`);});node.addEventListener('pointerup',e=>{if(!node.hasPointerCapture(e.pointerId))return;node.releasePointerCapture(e.pointerId);moveToValue(dx,dy);});};if(key==='coulomb')bindDrag(charge,dx=>{const input=$('#sim-dist');const next=Math.max(1,Math.min(50,Math.round(Number(input.value)+dx/1.5)));input.value=next;update();});const mirrorObject=svg.querySelector('#dragMirrorObject');if(key==='mirrors')bindDrag(mirrorObject,dx=>{const input=$('#sim-distance');input.value=Math.max(5,Math.min(100,Math.round(Number(input.value)-dx/3.65)));update();});const projectile=svg.querySelector('#dragProjectile');if(key==='projectile')bindDrag(projectile,(dx,dy)=>{const baseX=Math.cos(Number($('#sim-angle').value)*Math.PI/180)*Math.min(110,Number($('#sim-speed').value)*4),baseY=Math.sin(Number($('#sim-angle').value)*Math.PI/180)*Math.min(110,Number($('#sim-speed').value)*4);const px=baseX+dx,py=baseY-dy;const angle=Math.atan2(py,px)*180/Math.PI;const speed=Math.hypot(px,py)/4;$('#sim-angle').value=Math.max(5,Math.min(85,Math.round(angle)));$('#sim-speed').value=Math.max(1,Math.min(50,Math.round(speed)));update();});const probe=svg.querySelector('#dragProbe');if(key==='electric'||key==='potential')bindDrag(probe,dx=>{const id=$('#sim-dist');id.value=Math.max(Number(id.min),Math.min(Number(id.max),Math.round(Number(id.value)+dx/3)));update();});}function update(){const vals={};d.controls.forEach(([id])=>{const input=$('#sim-'+id);vals[id]=Number(input.value);$('#out-'+id).textContent=input.value;});if(key==='mirrors'){vals.mirrorType=$('#mirrorType').value;$('#sim-focal').closest('.control-row').style.display=vals.mirrorType==='plane'?'none':'';}if(key==='gauss'){vals.surfaceShape=$('#gaussShape').value;vals.chargePosition=$('#gaussPosition').value;}if(key==='waves')vals.medium=$('#waveMedium').value;const r=d.calc(vals);$('#simResult').textContent=r.value;$('#simUnit').textContent=r.unit;$('#simExplain').textContent=r.explain;$('#simVisual').textContent=r.visual;$('#simScene').innerHTML=simSceneSvg(key,vals);$('#simGraph').innerHTML=makeSimGraph(key,vals);$('#simMetrics').innerHTML=simMetrics(key,vals).map(([label,value,unit])=>`<div class="sim-metric"><span>${label}</span><strong>${value}</strong><small>${unit}</small></div>`).join('');$('#simInsight').innerHTML=`<strong>¿Qué debes observar?</strong><p>${simInsight(key,vals)}</p>`;$('#simScene').classList.toggle('show-grid',$('#simGrid').checked);$('#simScene').classList.toggle('hide-vectors',!$('#simVectors').checked);$('#simScene').classList.toggle('hide-labels',!$('#simLabels').checked);attachSceneDrag();}['simGrid','simVectors','simLabels'].forEach(id=>$('#'+id).addEventListener('change',()=>{if(id==='simGrid')$('#simScene').classList.toggle('show-grid',$('#simGrid').checked);if(id==='simVectors')$('#simScene').classList.toggle('hide-vectors',!$('#simVectors').checked);if(id==='simLabels')$('#simScene').classList.toggle('hide-labels',!$('#simLabels').checked);}));d.controls.forEach(([id])=>$('#sim-'+id).addEventListener('input',update));if(key==='mirrors')$('#mirrorType').addEventListener('change',update);if(key==='gauss'){['gaussShape','gaussPosition'].forEach(id=>$('#'+id).addEventListener('change',update));}if(key==='waves')$('#waveMedium').addEventListener('change',update);update();}

$("#simTabs").addEventListener("click",e=>{const b=e.target.closest("[data-sim]");if(b)renderSim(b.dataset.sim);});renderSim("coulomb");

// Formulas catalog and calculator formula solving
const formulas=[
{id:"coulomb",cat:"electricidad",title:"Ley de Coulomb",eq:"F = k · |q₁q₂| / r²",desc:"Fuerza eléctrica entre dos cargas puntuales.",vars:["q₁ (C)","q₂ (C)","r (m)"],units:["C","C","m"],solve:v=>({name:"F",value:8.9875517923e9*Math.abs(+v[0]*+v[1])/((+v[2])**2),unit:"N"})},
{id:"electric",cat:"electricidad",title:"Campo eléctrico",eq:"E = k · |Q| / r²",desc:"Campo creado por una carga puntual.",vars:["Q (C)","r (m)"],units:["C","m"],solve:v=>({name:"E",value:8.9875517923e9*Math.abs(+v[0])/((+v[1])**2),unit:"N/C"})},
{id:"gauss",cat:"electricidad",title:"Ley de Gauss",eq:"ΦE = Qenc / ε₀",desc:"Flujo eléctrico a través de una superficie cerrada.",vars:["Q encerrada (C)"],units:["C"],solve:v=>({name:"ΦE",value:+v[0]/8.8541878128e-12,unit:"N·m²/C"})},
{id:"potential",cat:"electricidad",title:"Potencial eléctrico",eq:"V = k · Q / r",desc:"Potencial debido a una carga puntual.",vars:["Q (C)","r (m)"],units:["C","m"],solve:v=>({name:"V",value:8.9875517923e9*(+v[0])/(+v[1]),unit:"V"})},
{id:"ohm",cat:"circuitos",title:"Ley de Ohm",eq:"V = I · R",desc:"Voltaje a partir de corriente y resistencia.",vars:["I (A)","R (Ω)"],units:["A","Ω"],solve:v=>({name:"V",value:+v[0]*+v[1],unit:"V"})},
{id:"magnetic",cat:"magnetismo",title:"Campo magnético (carga móvil)",eq:"F = |q| · v · B · sen θ",desc:"Fuerza magnética sobre una carga en movimiento.",vars:["q (C)","v (m/s)","B (T)","θ (°)"],units:["C","m/s","T","°"],solve:v=>({name:"F",value:Math.abs(+v[0])*+v[1]*+v[2]*Math.sin(+v[3]*Math.PI/180),unit:"N"})},
{id:"ampere",cat:"magnetismo",title:"Ley de Ampère (hilo recto largo)",eq:"B = μ₀ I / (2πr)",desc:"Campo magnético alrededor de un conductor rectilíneo largo.",vars:["I (A)","r (m)"],units:["A","m"],solve:v=>({name:"B",value:4*Math.PI*1e-7*(+v[0])/(2*Math.PI*+v[1]),unit:"T"})},
{id:"faraday",cat:"magnetismo",title:"Ley de Faraday",eq:"ε = −N · ΔΦ / Δt",desc:"FEM inducida por variación del flujo magnético.",vars:["N (espiras)","ΔΦ (Wb)","Δt (s)"],units:["espiras","Wb","s"],solve:v=>({name:"ε",value:-+v[0]*+v[1]/+v[2],unit:"V"})},
{id:"series",cat:"circuitos",title:"Circuito en serie",eq:"Rₑq = R₁ + R₂ + R₃",desc:"Resistencia equivalente de tres resistencias en serie.",vars:["R₁ (Ω)","R₂ (Ω)","R₃ (Ω)"],units:["Ω","Ω","Ω"],solve:v=>({name:"Rₑq",value:+v[0]+ +v[1]+ +v[2],unit:"Ω"})},
{id:"waves",cat:"ondas",title:"Ondas electromagnéticas",eq:"c = λ · f",desc:"Relación entre longitud de onda y frecuencia en el vacío.",vars:["λ (m)","f (Hz)"],units:["m","Hz"],solve:v=>({name:"c",value:+v[0]*+v[1],unit:"m/s"})},
{id:"reflection",cat:"optica",title:"Ley de reflexión",eq:"θᵢ = θᵣ",desc:"El ángulo de incidencia es igual al de reflexión.",vars:["θᵢ (°)"],units:["°"],solve:v=>({name:"θᵣ",value:+v[0],unit:"°"})},
{id:"mirror",cat:"optica",title:"Espejo plano",eq:"dᵢ = dₒ",desc:"La imagen se forma a la misma distancia detrás del espejo.",vars:["dₒ (cm)"],units:["cm"],solve:v=>({name:"dᵢ",value:+v[0],unit:"cm"})},
{id:"freefall",cat:"mecanica",title:"Caída libre desde el reposo",eq:"v = g · t",desc:"Velocidad tras caer durante un tiempo t, sin resistencia del aire.",vars:["g (m/s²)","t (s)"],units:["m/s²","s"],solve:v=>({name:"v",value:+v[0]*+v[1],unit:"m/s"})},
{id:"projectile",cat:"mecanica",title:"Tiro parabólico (alcance)",eq:"R = v₀² · sen(2θ) / g",desc:"Alcance horizontal cuando el proyectil aterriza a la altura de lanzamiento.",vars:["v₀ (m/s)","θ (°)","g (m/s²)"],units:["m/s","°","m/s²"],solve:v=>({name:"R",value:(+v[0])**2*Math.sin(2*+v[1]*Math.PI/180)/(+v[2]),unit:"m"})},
{id:"mru",cat:"mecanica",title:"MRU",eq:"Δx = v · t",desc:"Desplazamiento en movimiento rectilíneo uniforme.",vars:["v (m/s)","t (s)"],units:["m/s","s"],solve:v=>({name:"Δx",value:+v[0]*+v[1],unit:"m"})},
{id:"mruv",cat:"mecanica",title:"MRUV",eq:"v = v₀ + a · t",desc:"Velocidad final con aceleración constante.",vars:["v₀ (m/s)","a (m/s²)","t (s)"],units:["m/s","m/s²","s"],solve:v=>({name:"v",value:+v[0]+ +v[1]*+v[2],unit:"m/s"})},
{id:"work",cat:"mecanica",title:"Trabajo mecánico",eq:"W = F · d · cos θ",desc:"Trabajo realizado por una fuerza constante.",vars:["F (N)","d (m)","θ (°)"],units:["N","m","°"],solve:v=>({name:"W",value:+v[0]*+v[1]*Math.cos(+v[2]*Math.PI/180),unit:"J"})},
{id:"kinetic",cat:"mecanica",title:"Energía cinética",eq:"K = ½ · m · v²",desc:"Energía asociada al movimiento de un cuerpo.",vars:["m (kg)","v (m/s)"],units:["kg","m/s"],solve:v=>({name:"K",value:.5*+v[0]*(+v[1])**2,unit:"J"})},
{id:"expansion",cat:"termica",title:"Dilatación lineal",eq:"ΔL = α · L₀ · ΔT",desc:"Cambio de longitud por variación de temperatura.",vars:["α (1/°C)","L₀ (m)","ΔT (°C)"],units:["1/°C","m","°C"],solve:v=>({name:"ΔL",value:+v[0]*+v[1]*+v[2],unit:"m"})},
{id:"calor",cat:"termica",title:"Calorimetría",eq:"Q = m · c · ΔT",desc:"Calor sensible absorbido o cedido por una sustancia.",vars:["m (kg)","c (J/kg·°C)","ΔT (°C)"],units:["kg","J/kg·°C","°C"],solve:v=>({name:"Q",value:+v[0]*+v[1]*+v[2],unit:"J"})}
];
function renderFormulas(filter="all"){const items=filter==="all"?formulas:formulas.filter(f=>f.cat===filter);$("#formulaGrid").innerHTML=items.map((f,i)=>`<article class="formula-card"><h3>${f.title}</h3><div class="formula-equation">${f.eq}</div><p>${f.desc}</p><button data-use="${formulas.indexOf(f)}">Usar en la calculadora →</button></article>`).join("");$$("[data-use]").forEach(b=>b.onclick=()=>{setupFormulaSelect();$("#calcFormula").value=b.dataset.use;renderFormulaInputs();goPage("calculator");});}
$("#formulaFilter").addEventListener("click",e=>{const b=e.target.closest("[data-filter]");if(!b)return;$$("[data-filter]").forEach(x=>x.classList.toggle("selected",x===b));renderFormulas(b.dataset.filter);});renderFormulas();
function setupFormulaSelect(){$("#calcFormula").innerHTML=formulas.map((f,i)=>`<option value="${i}">${f.title} — ${f.eq}</option>`).join("");}
function renderFormulaInputs(){const f=formulas[Number($("#calcFormula").value)||0];$("#formulaInputs").innerHTML=f.vars.map((v,i)=>`<label class="field-label">${v}<input class="field-control formula-var" type="number" step="any" placeholder="Ingresa ${v}"></label>`).join("");$("#formulaResult").textContent="—";$("#formulaExplanation").textContent="Completa los datos y presiona calcular.";}
setupFormulaSelect();$("#calcFormula").onchange=renderFormulaInputs;renderFormulaInputs();
$("#solveFormula").onclick=()=>{const f=formulas[Number($("#calcFormula").value)||0];const inputs=$$(".formula-var").map(x=>x.value);if(inputs.some(x=>x.trim()==="")){toast("Completa todos los campos.");return;}if(inputs.some(x=>!Number.isFinite(Number(x)))){toast("Revisa los valores ingresados.");return;}const r=f.solve(inputs);if(!r||!Number.isFinite(r.value)){toast("No se puede calcular con esos valores.");return;}$("#formulaResult").textContent=`${r.name} = ${Number(r.value.toPrecision(6))} ${r.unit}`;$("#formulaExplanation").textContent="Resultado calculado a partir de la fórmula seleccionada.";};

// Basic calculator: safe arithmetic parser (only numeric operators and sqrt)
let calcExpr="";function showCalc(){ $("#calcDisplay").textContent=calcExpr||"0"; }
$("#calcKeys").addEventListener("click",e=>{const b=e.target.closest("[data-key]");if(!b)return;const k=b.dataset.key;if(k==="AC"){calcExpr="";showCalc();return;}if(k==="="){try{let expr=calcExpr.replace(/×/g,"*").replace(/÷/g,"/").replace(/−/g,"-");if(!/^[0-9+\-*/().\s]+$/.test(expr))throw Error();const result=Function('"use strict";return ('+expr+')')();if(!Number.isFinite(result))throw Error();calcExpr=String(Number(result.toPrecision(10)));}catch{calcExpr="Error";}showCalc();return;}if(k==="sqrt"){const n=Number(calcExpr);if(calcExpr===""||n<0||!Number.isFinite(n)){toast("Ingresa un número positivo.");return;}calcExpr=String(Math.sqrt(n));showCalc();return;}if(calcExpr==="Error")calcExpr="";calcExpr+=k;showCalc();});

// Unit converter
const unitSets={
length:{m:1,km:1000,cm:.01,mm:.001,mi:1609.344,ft:.3048},
mass:{kg:1,g:.001,mg:.000001,lb:.453592},
time:{s:1,min:60,h:3600,ms:.001},
speed:{"m/s":1,"km/h":1/3.6,mph:.44704},
force:{N:1,kN:1000,dyn:.00001,lbf:4.44822},
energy:{J:1,kJ:1000,cal:4.184,kWh:3600000,eV:1.602176634e-19},
charge:{C:1,mC:.001,"µC":1e-6,nC:1e-9},
voltage:{V:1,mV:.001,kV:1000}
};
function populateUnits(){const type=$("#conversionType").value,units=Object.keys(unitSets[type]);$("#fromUnit").innerHTML=units.map(u=>`<option>${u}</option>`).join("");$("#toUnit").innerHTML=units.map(u=>`<option>${u}</option>`).join("");$("#toUnit").selectedIndex=Math.min(1,units.length-1);convert();}
function convert(){const type=$("#conversionType").value,from=$("#fromUnit").value,to=$("#toUnit").value,val=Number($("#convertValue").value);if(!from||!to||!Number.isFinite(val))return;const result=val*unitSets[type][from]/unitSets[type][to];$("#convertedValue").value=Number(result.toPrecision(8));$("#conversionAnswer").textContent=`${Number(result.toPrecision(8))} ${to}`;}
$("#conversionType").onchange=populateUnits;$("#fromUnit").onchange=convert;$("#toUnit").onchange=convert;$("#convertValue").oninput=convert;$("#swapUnits").onclick=()=>{const a=$("#fromUnit").value,b=$("#toUnit").value;$("#fromUnit").value=b;$("#toUnit").value=a;convert();};populateUnits();

// Quiz: 32 questions covering the 16 syllabus topics
let questions = [];
let quizIndex = 0, quizAnswers = [], quizSubmitted = false, quizTopic = "";
function renderQuizSetup(errorText = "") {
  const safeError = errorText ? `<div class="quiz-feedback">${escapeHtml(errorText)}</div>` : "";
  $("#quizMain").innerHTML = `<div class="quiz-generator">
    <span class="question-topic">CUESTIONARIO PERSONALIZADO</span>
    <h2 class="question-text">¿Qué tema quieres practicar?</h2>
    <p class="quiz-generator-copy">Escribe un tema concreto o uno de los temas del curso. La IA elaborará preguntas originales y adaptadas al nivel elegido.</p>
    <label class="quiz-field-label" for="quizTopic">Tema o contenido</label>
    <input id="quizTopic" class="field-control" maxlength="180" placeholder="Ej. Ley de Faraday, espejos cóncavos, circuitos..." value="${escapeHtml(quizTopic)}">
    <div class="quiz-generator-grid">
      <label class="quiz-field-label">Dificultad<select id="quizDifficulty" class="field-control"><option value="Básica">Básica</option><option value="Intermedia" selected>Intermedia</option><option value="Avanzada">Avanzada</option></select></label>
      <label class="quiz-field-label">Número de preguntas<select id="quizCount" class="field-control"><option>5</option><option selected>10</option><option>15</option></select></label>
    </div>
    <button class="primary-btn full-btn" id="generateQuiz">✦ Generar cuestionario</button>
    <p class="quiz-generator-note">Las preguntas no están almacenadas previamente: se generan cuando pulsas el botón.</p>${safeError}
  </div>`;
  $("#generateQuiz").onclick = generateAiQuiz;
  typesetAssistantMath($("#quizMain"));
}
function escapeHtml(value) { return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }

// Interpreta el JSON de Gemini y corrige barras invertidas sin escapar dentro de textos.
// Gemini puede incluir comandos matemáticos como \\frac o \\theta, que no son escapes JSON.
function parseGeminiJson(raw) {
  const cleaned = String(raw ?? "")
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch (originalError) {
    let repaired = "";
    let insideString = false;

    for (let i = 0; i < cleaned.length; i++) {
      const char = cleaned[i];

      if (!insideString) {
        if (char === '"') insideString = true;
        repaired += char;
        continue;
      }

      if (char === '"') {
        // Las comillas solo cierran el texto si no están precedidas por una barra activa.
        let slashCount = 0;
        for (let j = i - 1; j >= 0 && cleaned[j] === "\\"; j--) slashCount++;
        if (slashCount % 2 === 0) insideString = false;
        repaired += char;
        continue;
      }

      if (char !== "\\") {
        repaired += char;
        continue;
      }

      const next = cleaned[i + 1] || "";
      const afterNext = cleaned[i + 2] || "";
      const isUnicodeEscape = next === "u" && /^[0-9a-fA-F]{4}$/.test(cleaned.slice(i + 2, i + 6));
      const isSimpleJsonEscape = '"\\/bfnrt'.includes(next);
      // Si después de \n, \t, \f, etc. continúa una palabra, normalmente es LaTeX
      // (por ejemplo \\theta, \\frac, \\text), no un escape JSON intencional.
      const looksLikeLatexCommand = /[A-Za-z]/.test(next) && /[A-Za-z]/.test(afterNext);
      const isValidEscape = isUnicodeEscape || (isSimpleJsonEscape && !looksLikeLatexCommand);

      if (isUnicodeEscape) {
        repaired += cleaned.slice(i, i + 6);
        i += 5;
      } else if (isValidEscape) {
        repaired += cleaned.slice(i, i + 2);
        i += 1;
      } else {
        repaired += "\\\\";
      }
    }

    try {
      return JSON.parse(repaired);
    } catch (repairError) {
      // Conserva el error original para que el diagnóstico no oculte la causa inicial.
      throw originalError;
    }
  }
}

async function generateAiQuiz() {
  const topic = $("#quizTopic").value.trim();
  const difficulty = $("#quizDifficulty").value;
  const count = Number($("#quizCount").value);
  if (!topic) { toast("Escribe el tema del cuestionario."); return; }
  quizTopic = topic;
  const button = $("#generateQuiz"); button.disabled = true; button.textContent = "Generando cuestionario…";
  try {
    if (!geminiApiKey && !configurarClaveGemini()) throw new Error("Debes configurar tu API key para consultar Gemini.");
    const quizLanguage = fisixLanguage === "en" ? "English" : "Spanish";
    const explanationLabel = fisixLanguage === "en" ? "A brief, clear explanation with the method or underlying principle" : "Explicación breve, clara y con el procedimiento o fundamento";
    const prompt = `Act as a university physics instructor. Create exactly ${count} original questions about: ${topic}. Difficulty: ${difficulty}. REQUIRED OUTPUT LANGUAGE: ${quizLanguage}. Write the title, every question, all four answer options, and every explanation entirely in ${quizLanguage}, regardless of the language used in the topic. Combine conceptual questions and numerical problems when appropriate. Each question must be self-contained and precise, with exactly four plausible options and only one correct answer. Return only valid JSON with this structure: {"title":"...","questions":[{"question":"...","options":["...","...","...","..."],"correctIndex":0,"explanation":"${explanationLabel}"}]}. correctIndex must be an integer from 0 to 3. Check calculations, units, signs, and answer keys. For mathematical expressions, use readable Unicode notation (for example, Δ, θ, π, √, ², ×, ÷) and avoid LaTeX commands or backslashes entirely so the JSON remains valid. Do not include Markdown or text outside the JSON.`;
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;
    let parsed = null;
    let lastParseError = null;

    // Gemini puede cortar una respuesta JSON larga, especialmente con 10 o 15 preguntas.
    // Si ocurre, se vuelve a solicitar una versión más compacta antes de mostrar un error.
    for (let attempt = 0; attempt < 2 && !parsed; attempt++) {
      const retryPrompt = attempt === 0 ? prompt : `${prompt}\n\nIMPORTANT RETRY: The previous output was incomplete. Return a COMPLETE, syntactically valid JSON object. Keep each explanation to one short sentence, keep all questions and four options, close every string/array/object, and do not stop before the final closing brace.`;
      const response = await fetch(url, {
        method:"POST",
        headers:{"Content-Type":"application/json","x-goog-api-key":geminiApiKey},
        body:JSON.stringify({
          contents:[{role:"user",parts:[{text:retryPrompt}]}],
          generationConfig:{responseMimeType:"application/json",temperature:0.3,maxOutputTokens:12288}
        })
      });
      if (!response.ok) {
        const data=await response.json().catch(()=>({}));
        throw new Error(data.error?.message || `Gemini respondió con el error HTTP ${response.status}.`);
      }
      const data = await response.json();
      const candidate = data.candidates?.[0];
      const raw = candidate?.content?.parts?.map(p=>p.text||"").join("").trim();
      if (!raw) {
        const reason = candidate?.finishReason;
        throw new Error(reason === "MAX_TOKENS"
          ? "Gemini cortó la respuesta por su límite de extensión. Intenta generar menos preguntas."
          : "Gemini no devolvió preguntas. Inténtalo nuevamente.");
      }
      try {
        parsed = parseGeminiJson(raw);
      } catch (error) {
        lastParseError = error;
        if (attempt === 1) {
          const reason = candidate?.finishReason;
          throw new Error(reason === "MAX_TOKENS"
            ? "Gemini está cortando el JSON porque el cuestionario es demasiado extenso. Prueba con 5 preguntas."
            : "Gemini devolvió un JSON incompleto o mal formado incluso después de reintentar. Vuelve a generar el cuestionario.");
        }
      }
    }
    if (!parsed) throw lastParseError || new Error("No se pudo interpretar el cuestionario generado.");
    if (!Array.isArray(parsed.questions) || parsed.questions.length !== count) throw new Error("El cuestionario generado no tiene la cantidad solicitada. Vuelve a intentarlo.");
    const valid = parsed.questions.every(q=>typeof q.question==="string" && Array.isArray(q.options) && q.options.length===4 && q.options.every(o=>typeof o==="string"&&o.trim()) && Number.isInteger(q.correctIndex)&&q.correctIndex>=0&&q.correctIndex<4 && typeof q.explanation==="string");
    if (!valid) throw new Error("Gemini generó un formato de preguntas no válido. Vuelve a intentarlo.");
    questions = parsed.questions.map((q,i)=>({topic:topic.toUpperCase(),q:q.question,a:q.options,c:q.correctIndex,e:q.explanation}));
    quizIndex=0; quizAnswers=Array(questions.length).fill(null); quizSubmitted=false;
    renderQuiz();
  } catch(error) { renderQuizSetup(error.message || "No se pudo generar el cuestionario."); }
}
function renderQuiz(){
  const q=questions[quizIndex];
  if(!q){renderQuizSetup();return;}
  const score=quizAnswers.filter((a,i)=>a===questions[i].c).length;
  $("#quizMain").innerHTML=`<div class="quiz-topline"><span>Pregunta ${quizIndex+1} de ${questions.length}</span><span>${Math.round((quizIndex+1)/questions.length*100)}% del cuestionario</span></div><div class="progress-track"><div class="progress-fill" style="width:${(quizIndex+1)/questions.length*100}%"></div></div><div class="question-topic">${escapeHtml(q.topic)}</div><h2 class="question-text">${escapeHtml(q.q)}</h2><div class="answers">${q.a.map((a,i)=>`<button class="answer-option ${quizAnswers[quizIndex]===i?"chosen":""} ${quizSubmitted&&i===q.c?"correct":quizSubmitted&&quizAnswers[quizIndex]===i&&i!==q.c?"wrong":""}" data-answer="${i}" ${quizSubmitted?"disabled":""}><span class="option-letter">${String.fromCharCode(65+i)}</span>${escapeHtml(a)}</button>`).join("")}</div>${quizSubmitted?`<div class="quiz-feedback"><b>${quizAnswers[quizIndex]===q.c?"¡Correcto!":"Respuesta incorrecta."}</b> ${escapeHtml(q.e)}</div>`:""}<div class="quiz-actions"><button class="soft-btn" id="prevQuestion" ${quizIndex===0?"disabled":""}>← Anterior</button>${quizIndex===questions.length-1?`<button class="primary-btn" id="finishQuiz">${quizSubmitted?"Ver resultado":"Finalizar cuestionario"}</button>`:`<button class="primary-btn" id="nextQuestion">Siguiente →</button>`}</div><div class="quiz-actions"><button class="soft-btn" id="newQuiz">＋ Crear otro cuestionario</button></div>`;
  $$('[data-answer]').forEach(b=>b.onclick=()=>{if(quizSubmitted)return;quizAnswers[quizIndex]=Number(b.dataset.answer);renderQuiz();});
  $("#prevQuestion").onclick=()=>{quizIndex--;renderQuiz();};
  if($("#nextQuestion"))$("#nextQuestion").onclick=()=>{if(quizAnswers[quizIndex]===null){toast("Selecciona una respuesta.");return;}quizIndex++;renderQuiz();};
  $("#newQuiz").onclick=()=>renderQuizSetup();
  typesetAssistantMath($("#quizMain"));
  if($("#finishQuiz"))$("#finishQuiz").onclick=()=>{if(!quizSubmitted){if(quizAnswers.includes(null)){toast("Responde todas las preguntas antes de finalizar.");return;}quizSubmitted=true;renderQuiz();return;}const total=questions.length;$("#quizMain").innerHTML=`<div class="quiz-result-screen"><div class="assistant-avatar">✦</div><div class="eyebrow">RESULTADO FINAL · ${escapeHtml(quizTopic)}</div><h2 style="font:800 28px Manrope">${score} / ${total}</h2><p style="color:#85899b;font-size:12px">Has respondido correctamente ${score} de ${total} preguntas.</p><button class="primary-btn" id="reviewQuiz">Revisar respuestas</button> <button class="soft-btn" id="restartQuiz">Repetir cuestionario</button> <button class="soft-btn" id="newQuizResult">Crear otro</button></div>`;$("#reviewQuiz").onclick=()=>{quizIndex=0;renderQuiz();};$("#restartQuiz").onclick=()=>{quizIndex=0;quizAnswers=Array(questions.length).fill(null);quizSubmitted=false;renderQuiz();};$("#newQuizResult").onclick=()=>renderQuizSetup();typesetAssistantMath($("#quizMain"));};
}
renderQuizSetup();


// Aplicar idioma guardado al iniciar y a los componentes generados dinámicamente.
applyFisixLanguage();

// Restaurar la sesión después de inicializar todas las variables y herramientas.
(function restoreLocalSession() {
  const username = localStorage.getItem(FISIX_SESSION_KEY);
  if (username && readLocalUsers()[username]) showFisixApp(username);
  else {
    localStorage.removeItem(FISIX_SESSION_KEY);
    $("#authScreen").hidden = false;
    $("#appShell").hidden = true;
  }
})();
