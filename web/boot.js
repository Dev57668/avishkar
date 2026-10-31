// Runs in <head> before first paint: enables the scroll-reveal styles only when JS runs and motion is allowed,
// so the page is fully visible without JavaScript or with reduced motion.
if (!matchMedia('(prefers-reduced-motion: reduce)').matches) document.documentElement.classList.add('motion');
