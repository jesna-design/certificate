(() => {
  const form = document.getElementById('lookup-form');
  const emailInput = document.getElementById('email');
  const button = document.getElementById('submit-button');
  const status = document.getElementById('form-message');
  const results = document.getElementById('results');
  const resultsHeading = document.querySelector('.results-heading');
  const participantName = document.getElementById('participant-name');
  const certificates = document.getElementById('certificate-list');
  const unavailableMessage = document.getElementById('unavailable-message');
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const defaultButtonText = button.textContent;

  function setStatus(message, state = '') {
    status.textContent = message;
    status.className = `form-message${state ? ` ${state}` : ''}`;
  }

  function clearResults() {
    results.hidden = true;
    resultsHeading.hidden = false;
    participantName.textContent = '';
    certificates.replaceChildren();
    unavailableMessage.hidden = true;
    unavailableMessage.textContent = '';
  }

  function showCertificate(item) {
    const card = document.createElement('article');
    card.className = 'certificate-card';
    const title = document.createElement('h3');
    title.textContent = item.title;
    card.append(title);

    if (!item.available || !item.token) {
      const message = document.createElement('p');
      message.textContent = 'This certificate is currently unavailable. Please contact the programme coordinator.';
      card.append(message);
      return card;
    }

    const download = document.createElement('a');
    download.className = 'download-button';
    download.href = `/api/certificates/${encodeURIComponent(item.token)}/download`;
    download.target = '_blank';
    download.rel = 'noopener noreferrer';
    download.textContent = `Download ${item.title}`;
    card.append(download);
    return card;
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    clearResults();
    setStatus('');
    const email = emailInput.value.trim();
    emailInput.value = email;
    if (!email || !emailInput.validity.valid) {
      setStatus('Unable to verify the email id', 'not-verified');
      emailInput.focus();
      return;
    }

    button.disabled = true;
    emailInput.disabled = true;
    button.textContent = 'Checking…';
    try {
      const response = await fetch('/api/lookup', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
        body: JSON.stringify({ email }),
      });
      const payload = await response.json();
      if (!response.ok) {
        setStatus('Unable to verify the email id', 'not-verified');
        return;
      }

      if (payload.certificate_record_missing) {
        setStatus('Verified', 'verified');
        resultsHeading.hidden = true;
        unavailableMessage.textContent = payload.error || 'No certificate record is available. Please contact the programme coordinator.';
        unavailableMessage.hidden = false;
        results.hidden = false;
        return;
      }
      setStatus('Verified', 'verified');
      participantName.textContent = payload.name;
      for (const item of payload.certificates || []) certificates.append(showCertificate(item));
      if (payload.both_unavailable) {
        unavailableMessage.textContent = 'Your participant record was found, but your certificates are currently unavailable. Please contact the programme coordinator.';
        unavailableMessage.hidden = false;
      }
      results.hidden = false;
      results.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (_) {
      setStatus('Unable to verify the email id', 'not-verified');
    } finally {
      button.disabled = false;
      emailInput.disabled = false;
      button.textContent = defaultButtonText;
    }
  });

  emailInput.addEventListener('input', () => {
    setStatus('');
    clearResults();
  });
})();
