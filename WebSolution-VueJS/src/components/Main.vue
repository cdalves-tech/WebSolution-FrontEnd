<template>
  <section class="hero">
        <div class="conteiner conteudo-hero">
            <div class="hero-texto">
                <h1>Desenvolvedor Front-End</h1>
                <h2 class="hero-subtitle">Interfaces modernas | Cloud AWS</h2>
                <p>Desenvolvo interfaces modernas e responsivas utilizando HTML, CSS, JavaScript e Vue.js, aplicando boas práticas de desenvolvimento. Tenho experiência com Git e GitHub para versionamento de código e deploy contínuo, além de certificação AWS Cloud Practitioner.</p>
                <a href="#" class="btn-grande">Ver Projetos</a>
            </div>

            <div class="hero-img">
                <img src="/src/assets/Images/banner-garoto.png" alt="">
            </div>
        </div>
    </section>
</template>

<script>
export default {
  name: 'Main'
}
</script>

<style scoped>
.hero {
    padding-top: 35px;
}

.hero .conteiner {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 40px;
}

.hero-texto h1 {
    font-size: 35px;
    font-weight: 700;
}

.hero-subtitle {
    font-size: 1.25rem;
    color: var(--texto-suave);
    margin-top: 8px;
}

.hero-texto p {
    font-size: 20px;
    color: var(--texto-suave);
    padding: 20px 0 40px;
}

/* BOTÃO GLOBAL */

.btn-grande {
    background-color: var(--cor-principal);
    color: var(--branco);
    padding: 14px 32px;
    border-radius: 8px;
    font-weight: 700;
    font-size: 17px;
    text-decoration: none;
    cursor: pointer;
    transition: background 0.3s;
}

.btn-grande:hover {
    background-color: var(--cor-hover);
}

</style>