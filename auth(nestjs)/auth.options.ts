export const jwtAccessSecret = process.env.JWT_ACCESS_SECRET;
export const jwtRefreshSecret = process.env.JWT_REFRESH_SECRET;
export const accessSignOptions = { expiresIn: '10h' };
export const refreshSignOptions = { expiresIn: '7d' };
