function checkPasswordStrength(password, confirmPassword) {
  const isLengthValid = password.length >= 8;
  document.getElementById("reqLength").className = isLengthValid
    ? "valid"
    : "invalid";
  document
    .getElementById("reqLength")
    .querySelector(".requirementIcon").textContent = isLengthValid ? "✓" : "✖";

  const hasDigit = /\d/.test(password);
  document.getElementById("reqDigit").className = hasDigit
    ? "valid"
    : "invalid";
  document
    .getElementById("reqDigit")
    .querySelector(".requirementIcon").textContent = hasDigit ? "✓" : "✖";

  const hasLetter = /[a-zA-Zа-яА-Я]/.test(password);
  document.getElementById("reqLetter").className = hasLetter
    ? "valid"
    : "invalid";
  document
    .getElementById("reqLetter")
    .querySelector(".requirementIcon").textContent = hasLetter ? "✓" : "✖";

  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  document.getElementById("reqSpecial").className = hasSpecial
    ? "valid"
    : "invalid";
  document
    .getElementById("reqSpecial")
    .querySelector(".requirementIcon").textContent = hasSpecial ? "✓" : "✖";

  const isMatch = password === confirmPassword && password !== "";
  document.getElementById("reqMatch").className = isMatch ? "valid" : "invalid";
  document
    .getElementById("reqMatch")
    .querySelector(".requirementIcon").textContent = isMatch ? "✓" : "✖";

  return isLengthValid && hasDigit && hasLetter && hasSpecial && isMatch;
}

document.getElementById("password").addEventListener("input", function () {
  const confirmPassword = document.getElementById("confirm_password").value;
  checkPasswordStrength(this.value, confirmPassword);
});

document
  .getElementById("confirm_password")
  .addEventListener("input", function () {
    const password = document.getElementById("password").value;
    checkPasswordStrength(password, this.value);
  });

document.querySelector("form").addEventListener("submit", function (e) {
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirm_password").value;

  if (!checkPasswordStrength(password, confirmPassword)) {
    e.preventDefault();
    alert("Пароль не соответствует требованиям безопасности!");
  }
});

document.querySelector(".themeSwitcher").addEventListener("click", function () {
  const isDark = !document.body.classList.contains("darkTheme");
  document.body.classList.toggle("darkTheme", isDark);

  localStorage.setItem("darkTheme", isDark);

  const icon = this.querySelector("img");
  if (icon) {
    icon.src = isDark
      ? "../../static/img/sun.png"
      : "../../static/img/moon.png";
  } else {
    console.warn(
      "Theme switcher icon not found. Ensure .themeSwitcher contains an <img> element."
    );
  }
});

document.addEventListener("DOMContentLoaded", function () {
  const isDark = localStorage.getItem("darkTheme") === "true";
  document.body.classList.toggle("darkTheme", isDark);

  const themeIcon = document.querySelector(".themeSwitcher img");
  if (themeIcon) {
    themeIcon.src = isDark
      ? "../../static/img/sun.png"
      : "../../static/img/moon.png";
  } else {
    console.warn(
      "Theme switcher icon not found during initialization. Ensure .themeSwitcher contains an <img> element."
    );
  }

  const dropZone = document.getElementById("dropZone");
  const avatarInput = document.getElementById("avatar");
  const avatarPreview = document.getElementById("avatarPreview");

  avatarInput.addEventListener("change", function (e) {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = function (event) {
        avatarPreview.src = event.target.result;
        avatarPreview.style.display = "block";
      };
      reader.readAsDataURL(file);
    }
  });

  dropZone.addEventListener("click", () => {
    avatarInput.click();
  });

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("dragover");
  });

  document.querySelector("form").addEventListener("submit", function (e) {
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirm_password").value;

    if (!checkPasswordStrength(password, confirmPassword)) {
      e.preventDefault();
      const lang = document.documentElement.lang;
      const message =
        lang === "ru"
          ? "Пароль не соответствует требованиям безопасности!"
          : "Password does not meet security requirements!";
      alert(message);
    }
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    const file = e.dataTransfer.files[0];
    if (file && file.type.startsWith("image/")) {
      avatarInput.files = e.dataTransfer.files;
      const reader = new FileReader();
      reader.onload = function (event) {
        avatarPreview.src = event.target.result;
        avatarPreview.style.display = "block";
      };
      reader.readAsDataURL(file);
    } else {
      alert("Пожалуйста, выберите изображение!");
    }
  });

  const modal = document.getElementById("registrationModal");
  const openBtn = document.querySelector(".openModalBtn");
  const closeBtn = document.querySelector(".closeBtn");

  const toggleModal = (shouldOpen) => {
    if (shouldOpen) {
      modal.showModal();
    } else {
      modal.close();
    }
  };

  openBtn.addEventListener("click", () => toggleModal(true));
  closeBtn.addEventListener("click", () => toggleModal(false));
  modal.addEventListener("click", (e) => {
    if (e.target === modal) toggleModal(false);
  });

  const phoneInput = document.getElementById("phone");
  phoneInput.addEventListener("focus", function () {
    if (!this.value.startsWith("+7")) this.value = "+7";
  });

  phoneInput.addEventListener("input", function (e) {
    const cursorPosition = this.selectionStart;
    let cleaned = this.value.replace(/\D/g, "");

    if (cleaned.startsWith("7") && !cleaned.startsWith("+7")) {
      cleaned = "7" + cleaned.substring(1);
    } else if (!cleaned.startsWith("7")) {
      cleaned = "7" + cleaned;
    }

    let formatted = "+7";
    if (cleaned.length > 1) {
      const rest = cleaned.substring(1);
      if (rest.length <= 3) {
        formatted += ` (${rest}`;
      } else if (rest.length <= 6) {
        formatted += ` (${rest.substring(0, 3)}) ${rest.substring(3)}`;
      } else if (rest.length <= 8) {
        formatted += ` (${rest.substring(0, 3)}) ${rest.substring(
          3,
          6
        )}-${rest.substring(6)}`;
      } else {
        formatted += ` (${rest.substring(0, 3)}) ${rest.substring(
          3,
          6
        )}-${rest.substring(6, 8)}-${rest.substring(8, 10)}`;
      }
    }

    this.value = formatted;
    this.setSelectionRange(
      e.inputType === "deleteContentBackward"
        ? cursorPosition
        : this.value.length,
      e.inputType === "deleteContentBackward"
        ? cursorPosition
        : this.value.length
    );
  });

  const emailInput = document.getElementById("email");
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const fullNameInput = document.getElementById("full_name");

  const validateEmail = () => {
    const isValid = emailRegex.test(emailInput.value);
    emailInput.setCustomValidity(
      isValid ? "" : "Пожалуйста, введите корректный email адрес"
    );
    if (!isValid) emailInput.reportValidity();
    return isValid;
  };

  const validateFullName = () => {
    const words = fullNameInput.value
      .trim()
      .split(/\s+/)
      .filter((word) => word.length > 0);
    const isValid = words.length >= 3;
    fullNameInput.setCustomValidity(
      isValid ? "" : "Пожалуйста, введите Фамилию, Имя и Отчество (3 слова)"
    );
    if (!isValid) fullNameInput.reportValidity();
    return isValid;
  };

  emailInput.addEventListener("blur", validateEmail);
  fullNameInput.addEventListener("blur", validateFullName);

  emailInput.addEventListener("input", function () {
    const isValid = validateEmail();
    document.querySelectorAll("input, textarea, button").forEach((element) => {
      if (element !== emailInput && element.id !== "submitButton") {
        element.disabled = !isValid;
      }
    });
  });

  document.querySelectorAll(".togglePassword").forEach((button) => {
    button.addEventListener("click", function () {
      const input = this.parentElement.querySelector("input");
      input.type = input.type === "password" ? "text" : "password";
    });
  });
});
