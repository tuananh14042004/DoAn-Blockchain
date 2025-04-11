// Đăng ký tài khoản
function register() {
    let username = document.getElementById("register-username").value;
    let password = document.getElementById("register-password").value;

    if (username && password) {
        let users = JSON.parse(localStorage.getItem("users")) || [];
        
        // Kiểm tra tên đăng nhập đã tồn tại chưa
        if (users.some(user => user.username === username)) {
            alert("Tên đăng nhập đã tồn tại!");
            return;
        }

        // Thêm người dùng mới
        users.push({ username, password });
        localStorage.setItem("users", JSON.stringify(users));
        alert("Đăng ký thành công!");
    } else {
        alert("Vui lòng nhập đầy đủ thông tin.");
    }
}

// Đăng nhập
function login() {
    let username = document.getElementById("login-username").value;
    let password = document.getElementById("login-password").value;

    let users = JSON.parse(localStorage.getItem("users")) || [];

    let user = users.find(user => user.username === username && user.password === password);

    if (user) {
        alert("Đăng nhập thành công!");
        window.location.href = "home.html"; // Chuyển đến trang chính
    } else {
        alert("Sai tài khoản hoặc mật khẩu!");
    }
}



