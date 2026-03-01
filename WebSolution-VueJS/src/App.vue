<template>
  <div id="app">
    <Header />
    <Main />
    <Services />
    <About />
    <Contact />
    <Footer />
  </div>
</template>

<script>
import Header from './components/header.vue'
import Main from './components/main.vue'
import Services from './components/Services.vue';
import About from './components/About.vue';
import Contact from './components/Contact.vue';
import Footer from './components/Footer.vue';

export default {
  name: 'App',
  components: {
    Header,
    Main,
    Services,
    About,
    Contact,
    Footer
  }
}
</script>

<style>

</style>