<template>
  <header class="menu">
        <div class="conteiner">
            <img class="logo" src="/src/assets/Images/web-solution 2.png" alt="">
            <nav class="navegar">
                <ul>
                    <li> <a href=".menu">Início</a></li>
                    <li> <a href=".servicos">Serviços</a></li>
                    <li> <a href=".sobre"> Sobre </a></li>
                    <li> <a href=".contato" class="btn-pequeno">Contato</a></li>
                </ul>
            </nav>
        </div>
    </header>
</template>

<script>
export default {
  name: 'Header'
}
</script>

<style scoped>
.menu {
    border-bottom: 1px solid var(--borda);
}

.menu .conteiner {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logo {
    font-size: 35px;
    font-weight: 700;
    cursor: pointer;
}

.navegar ul {
    display: flex;
    list-style: none;
    gap: 55px;
}

.navegar a {
    text-decoration: none;
    color: var(--texto);
    font-weight: 700;
    font-size: 17px;
}

.btn-pequeno {
    background-color: var(--cor-principal);
    color: var(--branco);
    padding: 12px 24px;
    border-radius: 8px;
}


</style>