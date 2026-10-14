# Installing yaklite with Homebrew

Once the tap is set up (below), anyone can install and update yaklite with:

    brew install fcgith/yaklite/yaklite
    brew upgrade yaklite

## One-time setup for the repository owner

1. Create an empty public GitHub repository named `homebrew-yaklite` under
   your account.
2. Create a fine-grained personal access token with "Contents: read and
   write" on that one repository only.
3. In this repository, add it as the Actions secret `HOMEBREW_TAP_TOKEN`
   (Settings > Secrets and variables > Actions).

From then on every release build writes `Formula/yaklite.rb` into the tap
from `yaklite.rb.tmpl`, with the new download address and checksum. Without
the secret the step is skipped.
