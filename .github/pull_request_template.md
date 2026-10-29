## Qué cambia

<!-- Una o dos frases. Si arregla un issue, enlázalo: Closes #123 -->

## Por qué

<!-- El problema real que resuelve, no solo la implementación. -->

## Cómo lo probé

<!-- Comandos, entorno (OS, versión de keepassxc-cli) y resultado. -->

```
bash scripts/keygate-selftest.sh
```

## Checklist

- [ ] `scripts/keygate-selftest.sh` pasa en local
- [ ] `python3 -m unittest discover -s tests -p 'test_*.py'` pasa
- [ ] No hay secretos, tokens ni rutas personales en el diff
- [ ] Si cambia comportamiento: README (es/en) y CHANGELOG actualizados
- [ ] El cambio es acotado (un problema por PR)
