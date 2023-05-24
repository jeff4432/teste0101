[12:39, 24/05/2023] Geovana: <?php
include("conexao.php");

$nome = filter_input(INPUT_POST, 'nome', FILTER_SANITIZE_STRING);
$email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
$senha = $_POST['senha'];

if (empty($nome) || empty($email) || empty($senha)) {
    die("Por favor, preencha todos os campos do formulário.");
}

$senhaHash = password_hash($senha, PASSWORD_DEFAULT);

$stmt = mysqli_prepare($conexao, "INSERT INTO cadastro (nome, email, senha) VALUES (?, ?, ?)");
mysqli_stmt_bind_param($stmt, "sss", $nome, $email, $senhaHash);

if (mysqli_stmt_execute($stmt)) {
    echo "Usuário cadastrado com sucesso";
} else {
    echo "Erro ao cadastrar usuário";
}

mysqli_stmt_close($stmt);
mysqli_close($conexao);
?>
[12:40, 24/05/2023] Geovana: conexao.php
[12:40, 24/05/2023] Geovana: <?php
    $servidor="localhost";
    $usuario="root";
    $senha="";
    $dbname="cadastro";

    
    $conexao=mysqli_connect($servidor, $usuario, $senha, $dbname );
    if(!$conexao){
        die("Houve um erro: " .mysqli_connect_error());

    }
?>