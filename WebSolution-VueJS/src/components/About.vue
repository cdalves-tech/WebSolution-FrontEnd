<template>
    <section class="sobre">
        <div class="conteiner sobre-nos">
            <div class="texto-sobre">
                <h2> Sobre Mim </h2>
                <p>conhecimentos em HTML, CSS, JavaScript e Vue.js, aplicados na criação de interfaces modernas, responsivas e funcionais.

Tenho experiência com Git e GitHub para versionamento e colaboração em projetos, seguindo boas práticas de desenvolvimento. Atualmente, estou ampliando minha formação em Cloud Computing pela Escola da Nuvem, possuo certificação AWS Certified Cloud Practitioner e concluí o programa AWS re/Start, adquirindo conhecimentos em serviços AWS e fundamentos de computação em nuvem.</p>
                <a href="https://www.linkedin.com/in/cdalves-tech" class="btn-grande" target="_blank">Saber Mais</a>
            </div>
            <div class="img-sobre">
                <img src="/src/assets/Images/banner-sobree.png" alt="">
            </div>
            
        </div>
    </section>
</template>

<script>
export default {
  name: 'About'
}
</script>

<style scoped>
.sobre-nos {
    display: flex;
    flex-direction: row-reverse;
    gap: 60px;
    align-items: center;
}

.texto-sobre h2 {
    font-size: 35px;
    margin-bottom: 20px;
}

.texto-sobre p {
    color: var(--texto-suave);
    margin-bottom: 50px;
}


</style>