export const playfair_en = (text, key, decrypt = false) => {
    const grid = [...new Set((key.toUpperCase() + "ABCDEFGHIKLMNOPQRSTUVWXYZ").replace(/J/g, 'I'))];
    
    let processed_user_text = text.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
    let pairs = [];
    for (let i = 0; i < processed_user_text.length; i += 2) {
        if (processed_user_text[i] === processed_user_text[i + 1]) {
            pairs.push(processed_user_text[i] + 'X');
            i--;
        } else {
            pairs.push(processed_user_text[i] + (processed_user_text[i + 1] || 'X'));
        }
    }

    const dir = decrypt ? 4 : 1;
    return pairs.map(pair => {
        let [char1, char2] = [grid.indexOf(pair[0]), grid.indexOf(pair[1])];
        let [row1, column1, row2, column2] = [~~(char1 / 5), char1 % 5, ~~(char2 / 5), char2 % 5];
        
        if (row1 === row2) {
            if (column1 === column2) {
                return grid[row1 * 5 + (column1 + dir) % 5];
            }
            return grid[row1 * 5 + (column1 + dir) % 5] + grid[row2 * 5 + (column2 + dir) % 5];
        }

        if (column1 === column2) {
            return grid[((row1 + dir) % 5) * 5 + column1] + grid[((row2 + dir) % 5) * 5 + column2];
        }
        
        return grid[row1 * 5 + column2] + grid[row2 * 5 + column1];
    }).join('');
};
