<template>
    <footer>
        <div class="icone-footer">
            <i class="bi bi-c-circle"> 2026 WebSolution. Todos os direitos reservados.</i>
            <div class="icones">
                <a href="https://www.linkedin.com/in/cdalves-tech" target="_blank"><i class="bi bi-linkedin"></i></a>
                <a href="https://github.com/cdalves-tech" target="_blank"><i class="bi bi-github"></i></a>
            </div>
            
        </div>
    </footer>
</template>

<script>
export default {
  name: 'Footer'
}
</script>

<style scoped>
footer {
    background-color: var(--rodape);
    color: var(--branco);
    text-align: center;
    padding: 30px 0;
}

.icones {
    margin-top: 20px;
    font-size: 27px;
}

.icones a {
    color: var(--branco);
    margin: 0 10px;
}

</style>