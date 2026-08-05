(() => {
    'use strict';

    const toggle = document.querySelector('.nav-toggle');
    const nav = document.querySelector('.site-nav');

    if (toggle && nav) {
        toggle.addEventListener('click', () => {
            const open = nav.classList.toggle('is-open');
            toggle.setAttribute('aria-expanded', String(open));
        });

        nav.querySelectorAll('a').forEach((link) => {
            link.addEventListener('click', () => {
                nav.classList.remove('is-open');
                toggle.setAttribute('aria-expanded', 'false');
            });
        });
    }

    const tabs = document.querySelectorAll('.command-tab');
    const panels = document.querySelectorAll('.command-code');

    tabs.forEach((tab) => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.target;
            tabs.forEach((item) => {
                const selected = item === tab;
                item.classList.toggle('is-active', selected);
                item.setAttribute('aria-selected', String(selected));
            });
            panels.forEach((panel) => panel.classList.toggle('is-active', panel.id === target));
        });
    });

    const stats = document.getElementById('repo-stats');
    const api = document.body.dataset.repositoryApi;

    if (stats && api) {
        fetch(api, { headers: { Accept: 'application/vnd.github+json' } })
            .then((response) => {
                if (!response.ok) throw new Error('Repository metadata unavailable');
                return response.json();
            })
            .then((repo) => {
                const stars = Number(repo.stargazers_count || 0).toLocaleString();
                const forks = Number(repo.forks_count || 0).toLocaleString();
                stats.textContent = `${stars} stars · ${forks} forks`;
            })
            .catch(() => {
                stats.textContent = 'public repository';
            });
    }
})();
