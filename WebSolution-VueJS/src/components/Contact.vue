<template>
    <section class="contato">
        <div class="conteiner contate-me">
            <h2>Entrar em Contato</h2>
            <form class="formulario">
                <div class="campo1">
                    <div class="campo">
                        <label for="nome" id="label-nome">Seu Nome</label>
                        <input type="text" id="nome">
                    </div>

                    <div class="campo">
                        <label for="email" id="label-email">Seu Email</label>
                        <input type="text" id="email">
                    </div>
                    <img src="/src/assets/Images/flor-sobre (1) (1) (1).png" alt="">
                </div>

                <div class="campo2">
                    <label for="mensagem" id="label-mensagem">Mensagem</label>
                    <textarea id="mensagem" placeholder="Sua Mensagem..."></textarea>
                    <button class="btn-grande teste">Enviar Mensagem</button>
                    <p id="mensagem-status"></p>
                </div>

            </form>
        </div>
    </section>
</template>

<script>
export default {
  name: 'Contact'
}
</script>

<style scoped>
.contato {
    background-color: var(--fundo);
    padding-bottom: 40px;
}

.contate-me h2 {
    font-size: 35px;
    text-align: center;
    margin-bottom: 20px;
}

.formulario {
    display: flex;
    background-color: var(--branco);
    border-radius: 30px;
    padding: 30px;
    gap: 40px;
}

.campo label,
.campo2 label {
    display: block;
    margin-bottom: 5px;
    color: var(--texto-suave);
}

.campo input,
.campo2 textarea {
    width: 100%;
    padding: 15px;
    border-radius: 10px;
    border: 1px solid var(--borda);
    font-size: 16px;
}

.campo2 textarea {
    height: 195px;
    resize: none;
}

.campo2 .btn-grande {
    margin-top: 20px;
    border: none;
}
</style>