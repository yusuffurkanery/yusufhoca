const todayDate = document.querySelector('#today-date');

if (todayDate) {
  const now = new Date();
  const options = {
    day: 'numeric',
    month: 'long',
    year: 'numeric'
  };
  todayDate.textContent = `Bugün: ${now.toLocaleDateString('tr-TR', options)}`;
}
