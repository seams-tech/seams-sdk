<script setup lang="ts">
import { computed, inject, ref, watchPostEffect } from 'vue';
import { useData } from 'vitepress';
import { VPImage, VPNavBarSearch } from 'vitepress/theme';

const { isDark, site, theme } = useData();

const brandHref = computed(() => {
  const link = theme.value.logoLink;
  return (typeof link === 'string' ? link : link?.link) ?? site.value.base;
});

// Layout provides the transition-aware toggle; the fallback keeps the switch
// working if this component is ever rendered outside it.
const toggleAppearance = inject('toggle-appearance', () => {
  isDark.value = !isDark.value;
});

const switchTitle = ref('');
watchPostEffect(() => {
  switchTitle.value = isDark.value ? 'Switch to light theme' : 'Switch to dark theme';
});
</script>

<template>
  <div class="seams-sidebar-header">
    <div class="seams-sidebar-header__top">
      <a class="seams-sidebar-header__brand" :href="brandHref" :aria-label="site.title">
        <VPImage class="seams-sidebar-header__logo" :image="theme.logo" alt="" />
      </a>
      <button
        class="seams-sidebar-header__appearance"
        type="button"
        role="switch"
        :title="switchTitle"
        :aria-label="switchTitle"
        :aria-checked="isDark"
        @click="toggleAppearance"
      >
        <span class="vpi-sun sun" aria-hidden="true" />
        <span class="vpi-moon moon" aria-hidden="true" />
      </button>
    </div>
    <VPNavBarSearch class="seams-sidebar-header__search" />
  </div>
</template>

<style scoped>
.seams-sidebar-header {
  margin-bottom: 24px;
}

.seams-sidebar-header__top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 16px;
}

.seams-sidebar-header__brand {
  display: inline-flex;
  align-items: center;
}

.seams-sidebar-header__brand :deep(.seams-sidebar-header__logo) {
  display: block;
  width: auto;
  height: 30px;
}

.seams-sidebar-header__appearance {
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  width: 30px;
  height: 30px;
  color: var(--vp-c-text-2);
  transition:
    border-color 0.25s,
    color 0.25s;
}

.seams-sidebar-header__appearance:hover {
  border-color: var(--vp-c-brand-1);
  color: var(--vp-c-brand-1);
}

.sun,
.moon {
  width: 15px;
  height: 15px;
}

/* The search button ships sized for the nav bar; in the sidebar it becomes a
   full-width field. */
.seams-sidebar-header__search {
  flex-grow: 0;
  padding: 0;
}

/* The button sits inside a wrapper div that is the flex item here. */
.seams-sidebar-header__search :deep(#local-search) {
  flex-grow: 1;
  width: 100%;
}

.seams-sidebar-header__search :deep(.DocSearch-Button) {
  margin: 0;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  width: 100%;
  height: 36px;
  background-color: var(--vp-c-bg);
  transition: border-color 0.25s;
}

.seams-sidebar-header__search :deep(.DocSearch-Button:hover) {
  border-color: var(--vp-c-brand-1);
  box-shadow: none;
}

.seams-sidebar-header__search :deep(.DocSearch-Button-Container) {
  flex-grow: 1;
}

/* The placeholder is hidden on narrow viewports for the nav bar; the sidebar
   has room for it at every width. */
.seams-sidebar-header__search :deep(.DocSearch-Button-Placeholder) {
  display: block;
  flex-grow: 1;
  padding: 0 8px;
  font-size: 13px;
  text-align: left;
}

.seams-sidebar-header__search :deep(.DocSearch-Button-Keys) {
  display: flex;
  min-width: auto;
}

.moon,
.dark .sun {
  display: none;
}

.dark .moon {
  display: block;
}
</style>
