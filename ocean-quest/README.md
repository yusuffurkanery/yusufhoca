# Ocean Quest

Ocean Quest, öğrencilerin ve öğretmenin aynı kalıcı Netlify Blobs deposunu kullandığı statik bir Netlify uygulamasıdır. Kimlik doğrulama `netlify/functions/api.mjs` içinde yapılır; öğrenci parolaları scrypt ile tuzlanmış hash olarak saklanır ve tarayıcıya gönderilmez.

## Admin kurulumu

İlk admin girişi, daha önce yayında bulunan geçici admin parolasıyla yapılır. Bu parola kaynak kodunda yayımlandığından güvenli kabul edilmemelidir; girişten hemen sonra admin panelindeki **Şifre Değiştir** formundan yeni bir parola belirleyin. Yeni parola hiçbir zaman tarayıcıda veya veritabanında düz metin saklanmaz; scrypt hash'i Netlify Blobs'ta tutulur.

Admin panelinden oluşturulan öğrenci hesapları da scrypt hash'iyle buluta kaydedilir. Uygulama verileri Netlify Blobs'ta kalıcıdır; anonim kullanıcıların okuma/yazma istekleri API tarafından reddedilir.
