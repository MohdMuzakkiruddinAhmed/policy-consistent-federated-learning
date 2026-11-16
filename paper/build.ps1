$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if (-not (Get-Command pdflatex -ErrorAction SilentlyContinue)) {
        throw 'Install MiKTeX or TeX Live, or upload the source to Overleaf.'
    }
    for ($posterPass = 1; $posterPass -le 2; $posterPass++) {
        & pdflatex -interaction=nonstopmode -halt-on-error pcfl-poster.tex
        if ($LASTEXITCODE -ne 0) { throw "pdfLaTeX failed on pass $posterPass." }
    }
    $posterLog = Get-Content -LiteralPath 'pcfl-poster.log' -Raw
    if ($posterLog -match 'There were undefined references|Citation .+ undefined|Reference .+ undefined|Overfull \\[hv]box') {
        throw 'Inspect the LaTeX log: unresolved references or overflowing content.'
    }
    if (Get-Command pdfinfo -ErrorAction SilentlyContinue) {
        $posterInfo = & pdfinfo pcfl-poster.pdf
        if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the generated PDF.' }
        $posterPages = $posterInfo | Select-String '^Pages:\s+3$'
        if (-not $posterPages) { throw 'The paper must contain exactly three pages, including references.' }
        $posterInfo | Select-String '^Pages:|^Page size:'
    }
    if (Get-Command pdffonts -ErrorAction SilentlyContinue) {
        & pdffonts pcfl-poster.pdf
        if ($LASTEXITCODE -ne 0) { throw 'Could not inspect PDF fonts.' }
    }
    Write-Output 'Built the poster paper. Visually inspect all pages after editing.'
}
finally {
    Pop-Location
}
