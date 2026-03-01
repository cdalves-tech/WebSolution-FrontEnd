<template>
    <section class="servicos">
        <div class="conteiner conteudo-servicos">

            <h2>O que eu faço</h2>

            <div class="caixas">

                <div class="caixa1">
                    <img src="/src/assets/Images/4.png" alt="">
                    <h3>Interfaces Web</h3>
                    <p>Interfaces modernas e responsivas com HTML, CSS e JavaScript.</p>
                </div>

                <div class="caixa2">
                    <img src="/src/assets/Images/aws3.png" alt="">
                    <h3>Cloud Computing</h3>
                    <p>Deploy e serviços em nuvem com AWS Cloud Practitioner.</p>
                </div>

                <div class="caixa3">
                    <img src="/src/assets/Images/aprendizado (1).png" alt="">
                    <h3>Aprendizado Contínuo</h3>
                    <p>Sempre evoluindo e aplicando boas práticas do mercado.</p>
                </div>

            </div>  
        </div>
    </section>
</template>


<script>
export default {
  name: 'Services'
}
</script>

<style scoped>
.servicos {
    background-color: var(--fundo);
}

.servicos h2 {
    font-size: 35px;
    text-align: center;
    margin-bottom: 40px;
}

.caixas {
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 20px;
    padding-bottom: 40px;
}

.caixas > div {
    width: 420px;
    height: 300px;
    padding: 25px;
    border-radius: 12px;
    background-color: var(--branco);
    text-align: center;
    border: 1px solid transparent;
    transition: transform 0.35s ease, box-shadow 0.35s ease;
}

.caixas > div:hover {
    transform: translateY(-8px) scale(1.02);
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.08);
    border: 1px solid var(--borda);
    cursor: pointer;
}

.caixas img {
    transition: transform 0.35s ease;
}

.caixas > div:hover img {
    transform: scale(1.1);
}

.caixas p {
    margin-top: 10px;
    color: var(--texto-suave);
}

</style>